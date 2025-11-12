"""
VPC metadata storage and retrieval using NDJSON format.
Manages persistent metadata for VPCs and peering connections.
"""
import json
import os
import logging

logger = logging.getLogger("vpcctl.core.metadata")

METADATA_DIR = "/var/lib/vpcctl"
VPC_METADATA_FILE = os.path.join(METADATA_DIR, "vpcs.ndjson")
PEERING_METADATA_FILE = os.path.join(METADATA_DIR, "peerings.ndjson")


def ensure_metadata_dir():
    """Ensure metadata directory exists."""
    os.makedirs(METADATA_DIR, exist_ok=True)


def save_vpc_metadata(vpc_data: dict):
    """Append VPC metadata to the NDJSON file."""
    ensure_metadata_dir()
    with open(VPC_METADATA_FILE, "a") as f:
        f.write(json.dumps(vpc_data) + "\n")
    logger.info(f"Saved metadata for VPC: {vpc_data.get('name')}")


def load_vpc_metadata():
    """Load all VPC metadata from NDJSON file."""
    if not os.path.exists(VPC_METADATA_FILE):
        return []
    
    vpcs = []
    with open(VPC_METADATA_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                vpcs.append(json.loads(line))
    return vpcs


def find_vpc_by_name(vpc_name: str):
    """Find VPC metadata by name."""
    vpcs = load_vpc_metadata()
    for vpc in vpcs:
        if vpc.get("name") == vpc_name:
            return vpc
    return None


def delete_vpc_metadata(vpc_name: str):
    """Remove VPC metadata from NDJSON file."""
    vpcs = load_vpc_metadata()
    remaining = [v for v in vpcs if v.get("name") != vpc_name]
    
    with open(VPC_METADATA_FILE, "w") as f:
        for vpc in remaining:
            f.write(json.dumps(vpc) + "\n")
    
    logger.info(f"Deleted metadata for VPC: {vpc_name}")


def save_peering_metadata(peering_data: dict):
    """Append peering metadata to the NDJSON file."""
    ensure_metadata_dir()
    with open(PEERING_METADATA_FILE, "a") as f:
        f.write(json.dumps(peering_data) + "\n")
    logger.info(f"Saved peering metadata: {peering_data.get('vpc1')} <-> {peering_data.get('vpc2')}")


def load_peering_metadata():
    """Load all peering metadata from NDJSON file."""
    if not os.path.exists(PEERING_METADATA_FILE):
        return []
    
    peerings = []
    with open(PEERING_METADATA_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                peerings.append(json.loads(line))
    return peerings


def find_peering(vpc1: str, vpc2: str):
    """Find peering metadata between two VPCs (order-independent)."""
    peerings = load_peering_metadata()
    for peering in peerings:
        if {peering.get("vpc1"), peering.get("vpc2")} == {vpc1, vpc2}:
            return peering
    return None


def delete_peering_metadata(vpc1: str, vpc2: str):
    """Remove peering metadata from NDJSON file."""
    peerings = load_peering_metadata()
    remaining = [
        p for p in peerings
        if {p.get("vpc1"), p.get("vpc2")} != {vpc1, vpc2}
    ]
    
    with open(PEERING_METADATA_FILE, "w") as f:
        for peering in remaining:
            f.write(json.dumps(peering) + "\n")
    
    logger.info(f"Deleted peering metadata: {vpc1} <-> {vpc2}")
