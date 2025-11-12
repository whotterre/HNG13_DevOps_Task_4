"""
VPC peering operations: peer and unpeer VPCs.
"""
import argparse
import subprocess
import os
import json
import logging

from .utils import get_hash
from .checks import check_veth_exists, check_netns_exists
from .metadata import (
    load_vpc_metadata,
    find_vpc_by_name,
    save_peering_metadata,
    load_peering_metadata,
    find_peering,
    delete_peering_metadata
)

logger = logging.getLogger("vpcctl.core.peering")


def _short_hash(s: str, max_len: int) -> str:
    """Generate short hash for resource naming."""
    h = get_hash(s)
    return h[:max_len]


def peer_vpcs(args: argparse.Namespace = None) -> int:
    """
    Create a peering connection between two VPCs by connecting their bridges
    with a veth pair and adding static routes for cross-VPC traffic.
    """
    first_vpc = getattr(args, "vpc1", None)
    second_vpc = getattr(args, "vpc2", None)
    dry_run = getattr(args, "dry_run", False)

    if not first_vpc or not second_vpc:
        logger.error("Both --vpc1 and --vpc2 must be provided")
        return 1

    if first_vpc == second_vpc:
        logger.error("Cannot peer a VPC with itself")
        return 1

    logger.info("Creating peering connection between VPC %s and VPC %s", first_vpc, second_vpc)

    if dry_run:
        logger.info("DRY-RUN: would create peering connection between %s and %s", first_vpc, second_vpc)
        return 0

    # Load VPC records
    first_vpc_rec = find_vpc_by_name(first_vpc)
    second_vpc_rec = find_vpc_by_name(second_vpc)

    if not first_vpc_rec:
        logger.error("VPC %s not found in metadata", first_vpc)
        return 1
    if not second_vpc_rec:
        logger.error("VPC %s not found in metadata", second_vpc)
        return 1

    # Extract bridge names and CIDRs
    bridge1 = first_vpc_rec.get("bridge")
    bridge2 = second_vpc_rec.get("bridge")
    cidr1_pub = first_vpc_rec.get("public_subnet")
    cidr1_pri = first_vpc_rec.get("private_subnet")
    cidr2_pub = second_vpc_rec.get("public_subnet")
    cidr2_pri = second_vpc_rec.get("private_subnet")

    if not bridge1 or not bridge2:
        logger.error("Bridge names not found in VPC metadata")
        return 1

    # Create peering veth pair name (deterministic from sorted VPC names)
    peer_names = sorted([first_vpc, second_vpc])
    peer_id = _short_hash("-".join(peer_names), 8)
    veth_peer1 = f"peer-{peer_id}-a"
    veth_peer2 = f"peer-{peer_id}-b"

    # Check if peering already exists
    if check_veth_exists(veth_peer1):
        logger.warning("Peering veth %s already exists; connection may already be established", veth_peer1)
        return 0

    try:
        # Create veth pair
        subprocess.run(["ip", "link", "add", veth_peer1, "type", "veth", "peer", "name", veth_peer2],
                      check=True, capture_output=True, text=True)
        logger.info("Created peering veth pair: %s <-> %s", veth_peer1, veth_peer2)

        # Attach each end to respective bridge
        subprocess.run(["ip", "link", "set", veth_peer1, "master", bridge1],
                      check=True, capture_output=True, text=True)
        logger.info("Attached %s to bridge %s", veth_peer1, bridge1)

        subprocess.run(["ip", "link", "set", veth_peer2, "master", bridge2],
                      check=True, capture_output=True, text=True)
        logger.info("Attached %s to bridge %s", veth_peer2, bridge2)

        # Bring up both ends
        subprocess.run(["ip", "link", "set", veth_peer1, "up"],
                      check=True, capture_output=True, text=True)
        subprocess.run(["ip", "link", "set", veth_peer2, "up"],
                      check=True, capture_output=True, text=True)
        logger.info("Brought up peering veth pair")

        # Add static routes on each bridge for the other VPC's subnets
        bridge1_ip = first_vpc_rec.get("bridge_ip", "").split("/")[0] if first_vpc_rec.get("bridge_ip") else None
        bridge2_ip = second_vpc_rec.get("bridge_ip", "").split("/")[0] if second_vpc_rec.get("bridge_ip") else None

        # Routes on bridge1 for VPC2 subnets via bridge2
        if bridge2_ip and cidr2_pub:
            try:
                subprocess.run(["ip", "route", "add", cidr2_pub, "via", bridge2_ip, "dev", bridge1],
                              check=True, capture_output=True, text=True)
                logger.info("Added route: %s via %s on bridge %s", cidr2_pub, bridge2_ip, bridge1)
            except subprocess.CalledProcessError as e:
                logger.warning("Route may already exist or failed: %s", str(e))

        if bridge2_ip and cidr2_pri:
            try:
                subprocess.run(["ip", "route", "add", cidr2_pri, "via", bridge2_ip, "dev", bridge1],
                              check=True, capture_output=True, text=True)
                logger.info("Added route: %s via %s on bridge %s", cidr2_pri, bridge2_ip, bridge1)
            except subprocess.CalledProcessError as e:
                logger.warning("Route may already exist or failed: %s", str(e))

        # Routes on bridge2 for VPC1 subnets via bridge1
        if bridge1_ip and cidr1_pub:
            try:
                subprocess.run(["ip", "route", "add", cidr1_pub, "via", bridge1_ip, "dev", bridge2],
                              check=True, capture_output=True, text=True)
                logger.info("Added route: %s via %s on bridge %s", cidr1_pub, bridge1_ip, bridge2)
            except subprocess.CalledProcessError as e:
                logger.warning("Route may already exist or failed: %s", str(e))

        if bridge1_ip and cidr1_pri:
            try:
                subprocess.run(["ip", "route", "add", cidr1_pri, "via", bridge1_ip, "dev", bridge2],
                              check=True, capture_output=True, text=True)
                logger.info("Added route: %s via %s on bridge %s", cidr1_pri, bridge1_ip, bridge2)
            except subprocess.CalledProcessError as e:
                logger.warning("Route may already exist or failed: %s", str(e))

        # Persist peering metadata
        peering_record = {
            "vpc1": first_vpc,
            "vpc2": second_vpc,
            "veth1": veth_peer1,
            "veth2": veth_peer2,
            "bridge1": bridge1,
            "bridge2": bridge2,
        }
        save_peering_metadata(peering_record)

        logger.info("Successfully created peering connection between %s and %s", first_vpc, second_vpc)
        return 0

    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to create peering connection: %s", stderr)
        return 1
    except Exception as e:
        logger.error("Unexpected error during peering: %s", str(e))
        return 1


def unpeer_vpcs(args: argparse.Namespace = None) -> int:
    """
    Remove a peering connection between two VPCs by deleting the veth pair
    and removing static routes.
    """
    first_vpc = getattr(args, "vpc1", None)
    second_vpc = getattr(args, "vpc2", None)
    dry_run = getattr(args, "dry_run", False)

    if not first_vpc or not second_vpc:
        logger.error("Both --vpc1 and --vpc2 must be provided")
        return 1

    logger.info("Removing peering connection between VPC %s and VPC %s", first_vpc, second_vpc)

    if dry_run:
        logger.info("DRY-RUN: would remove peering connection between %s and %s", first_vpc, second_vpc)
        return 0

    # Load peering record
    peering_rec = find_peering(first_vpc, second_vpc)

    if not peering_rec:
        logger.warning("No peering record found between %s and %s", first_vpc, second_vpc)
        # Try deterministic names anyway
        peer_names = sorted([first_vpc, second_vpc])
        peer_id = _short_hash("-".join(peer_names), 8)
        veth_peer1 = f"peer-{peer_id}-a"
    else:
        veth_peer1 = peering_rec.get("veth1")

    # Delete veth pair (deleting one end removes both)
    try:
        if veth_peer1 and check_veth_exists(veth_peer1):
            subprocess.run(["ip", "link", "delete", veth_peer1, "type", "veth"],
                          check=True, capture_output=True, text=True)
            logger.info("Deleted peering veth %s", veth_peer1)
        else:
            logger.warning("Peering veth %s not found", veth_peer1 if veth_peer1 else "<unknown>")
    except subprocess.CalledProcessError as e:
        logger.warning("Failed to delete peering veth: %s", str(e))

    # Remove static routes
    if peering_rec:
        first_vpc_rec = find_vpc_by_name(first_vpc)
        second_vpc_rec = find_vpc_by_name(second_vpc)

        if first_vpc_rec and second_vpc_rec:
            bridge1 = first_vpc_rec.get("bridge")
            bridge2 = second_vpc_rec.get("bridge")
            cidr1_pub = first_vpc_rec.get("public_subnet")
            cidr1_pri = first_vpc_rec.get("private_subnet")
            cidr2_pub = second_vpc_rec.get("public_subnet")
            cidr2_pri = second_vpc_rec.get("private_subnet")
            bridge1_ip = first_vpc_rec.get("bridge_ip", "").split("/")[0] if first_vpc_rec.get("bridge_ip") else None
            bridge2_ip = second_vpc_rec.get("bridge_ip", "").split("/")[0] if second_vpc_rec.get("bridge_ip") else None

            # Remove routes from bridge1
            for cidr in [cidr2_pub, cidr2_pri]:
                if cidr and bridge2_ip:
                    try:
                        subprocess.run(["ip", "route", "del", cidr, "via", bridge2_ip, "dev", bridge1],
                                      capture_output=True, text=True)
                        logger.info("Removed route: %s via %s on bridge %s", cidr, bridge2_ip, bridge1)
                    except subprocess.CalledProcessError:
                        pass

            # Remove routes from bridge2
            for cidr in [cidr1_pub, cidr1_pri]:
                if cidr and bridge1_ip:
                    try:
                        subprocess.run(["ip", "route", "del", cidr, "via", bridge1_ip, "dev", bridge2],
                                      capture_output=True, text=True)
                        logger.info("Removed route: %s via %s on bridge %s", cidr, bridge1_ip, bridge2)
                    except subprocess.CalledProcessError:
                        pass

    # Remove peering metadata
    delete_peering_metadata(first_vpc, second_vpc)

    logger.info("Finished unpeering VPCs %s and %s", first_vpc, second_vpc)
    return 0
