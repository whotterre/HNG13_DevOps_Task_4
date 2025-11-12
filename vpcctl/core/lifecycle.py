"""
VPC lifecycle management: create, list, inspect, delete operations.
"""
import argparse
import subprocess
import ipaddress
import os
import json
import logging
import re

from .utils import get_hash, get_rand_int
from .checks import (
    check_bridge_exists,
    check_netns_exists,
    check_veth_exists,
    check_veth_in_netns,
    find_interface_namespace,
    check_ip_on_interface,
    check_ip_in_netns,
    check_route_in_netns,
    check_iptables_rule_exists,
    check_ip_forward_enabled
)
from .metadata import (
    save_vpc_metadata,
    load_vpc_metadata,
    find_vpc_by_name,
    delete_vpc_metadata
)

logger = logging.getLogger("vpcctl.core.lifecycle")


def _short_hash(s: str, max_len: int) -> str:
    """Generate short hash for resource naming."""
    h = get_hash(s)
    return h[:max_len]


def create_vpc(args: argparse.Namespace) -> int:
    """Create a new VPC with public and private subnets."""
    dry_run = getattr(args, "dry_run", False)

    name = getattr(args, "name", None)
    cidr = getattr(args, "cidr", None)
    public_subnet = getattr(args, "public_subnet", None)
    private_subnet = getattr(args, "private_subnet", None)
    interface = getattr(args, "interface", None)

    if not name:
        logger.error("VPC name must be provided")
        return 1
    if not cidr:
        logger.error("CIDR value must be provided")
        return 1
    if not public_subnet:
        logger.error("Public subnet value must be provided")
        return 1
    if not private_subnet:
        logger.error("Private subnet value must be provided")
        return 1
    if not interface:
        logger.error("Interface value must be provided")
        return 1

    logger.info("Preparing to create VPC %s", name)

    if dry_run:
        logger.info("DRY-RUN: would create VPC with: name=%s cidr=%s public=%s private=%s interface=%s",
                    name, cidr, public_subnet, private_subnet, interface)
        return 0

    bridge_name = "br-" + _short_hash(name, 11)

    # Create bridge
    try:
        if check_bridge_exists(bridge_name):
            logger.info("Bridge %s already exists", bridge_name)
        else:
            logger.info("Creating bridge with name %s", bridge_name)
            subprocess.run(["ip", "link", "add", bridge_name, "type", "bridge"], check=True)
            logger.info("Successfully created bridge %s", bridge_name)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to create bridge: %s", stderr)
        return 1

    # Validate CIDR and assign IP to bridge
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception as e:
        logger.error("Invalid CIDR provided: %s", cidr)
        return 1

    hosts = list(net.hosts())
    if not hosts:
        logger.error("CIDR %s has no usable addresses", cidr)
        return 1

    candidate_ips = hosts[1:] if len(hosts) > 1 else hosts

    try:
        ip_addr = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True, check=True).stdout
    except subprocess.CalledProcessError as e:
        logger.error("Failed to query local addresses: %s", e)
        return 1

    chosen_ip = None
    for ip in candidate_ips:
        ip_with_prefix = f"{ip}/{net.prefixlen}"
        if check_ip_on_interface(bridge_name, ip_with_prefix):
            logger.info("IP %s already assigned to bridge %s", ip_with_prefix, bridge_name)
            chosen_ip = ip
            break
        if ip_with_prefix in ip_addr:
            logger.debug("IP %s already present on host, skipping", ip_with_prefix)
            continue
        chosen_ip = ip
        break

    if chosen_ip is None:
        logger.error("No free IP addresses found in %s", cidr)
        return 1

    ip_str = f"{chosen_ip}/{net.prefixlen}"

    if not check_ip_on_interface(bridge_name, ip_str):
        logger.info("Assigning IP %s to bridge %s", ip_str, bridge_name)
        try:
            subprocess.run(["ip", "addr", "add", ip_str, "dev", bridge_name], check=True, capture_output=True, text=True)
            logger.info("Assigned %s to %s", ip_str, bridge_name)
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.strip() if e.stderr else str(e)
            logger.error("Failed to assign IP: %s", stderr)
            return 1

    # Bring bridge up
    try:
        result = subprocess.run(["ip", "link", "show", bridge_name], capture_output=True, text=True, check=True)
        if "state UP" not in result.stdout and "state UNKNOWN" not in result.stdout:
            subprocess.run(["ip", "link", "set", bridge_name, "up"], check=True, capture_output=True, text=True)
            logger.info("Brought bridge %s up", bridge_name)
        else:
            logger.info("Bridge %s already up", bridge_name)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to bring bridge up: %s", stderr)
        return 1

    # Create network namespaces
    private_ns = "vpc-pr-ns-" + _short_hash(name + str(get_rand_int()), 8)
    public_ns = "vpc-pub-ns-" + _short_hash(name + str(get_rand_int()), 8)

    try:
        if check_netns_exists(private_ns):
            logger.info("Network namespace %s already exists", private_ns)
        else:
            subprocess.run(["ip", "netns", "add", private_ns], check=True, capture_output=True, text=True)
            logger.info("Created network namespace for private subnet: %s", private_ns)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to create network namespace for private subnet: %s", stderr)
        return 1

    try:
        if check_netns_exists(public_ns):
            logger.info("Network namespace %s already exists", public_ns)
        else:
            subprocess.run(["ip", "netns", "add", public_ns], check=True, capture_output=True, text=True)
            logger.info("Created network namespace for public subnet: %s", public_ns)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to create network namespace for public subnet: %s", stderr)
        return 1

    # Create veth pairs
    veth_pub_host = "veth-" + _short_hash(name + "-pub-h", 10)
    veth_pub_ns = "veth-" + _short_hash(name + "-pub-n", 10)
    veth_pri_host = "veth-" + _short_hash(name + "-pri-h", 10)
    veth_pri_ns = "veth-" + _short_hash(name + "-pri-n", 10)

    try:
        if check_veth_exists(veth_pub_host) or check_veth_in_netns(public_ns, veth_pub_ns):
            logger.info("Public veth pair already exists")
        else:
            subprocess.run(["ip", "link", "add", veth_pub_host, "type", "veth", "peer", "name", veth_pub_ns],
                         check=True, capture_output=True, text=True)
            logger.info("Created public veth pair: %s<->%s", veth_pub_host, veth_pub_ns)

        if check_veth_exists(veth_pri_host) or check_veth_in_netns(private_ns, veth_pri_ns):
            logger.info("Private veth pair already exists")
        else:
            subprocess.run(["ip", "link", "add", veth_pri_host, "type", "veth", "peer", "name", veth_pri_ns],
                         check=True, capture_output=True, text=True)
            logger.info("Created private veth pair: %s<->%s", veth_pri_host, veth_pri_ns)

        # Attach veth to bridge
        if check_veth_exists(veth_pub_host):
            result = subprocess.run(["ip", "link", "show", veth_pub_host], capture_output=True, text=True)
            if f"master {bridge_name}" not in result.stdout:
                subprocess.run(["ip", "link", "set", veth_pub_host, "master", bridge_name],
                             check=True, capture_output=True, text=True)
                logger.info("Attached %s to bridge", veth_pub_host)

            if "state UP" not in result.stdout:
                subprocess.run(["ip", "link", "set", veth_pub_host, "up"], check=True, capture_output=True, text=True)
                logger.info("Brought %s up", veth_pub_host)

        if check_veth_exists(veth_pri_host):
            result = subprocess.run(["ip", "link", "show", veth_pri_host], capture_output=True, text=True)
            if f"master {bridge_name}" not in result.stdout:
                subprocess.run(["ip", "link", "set", veth_pri_host, "master", bridge_name],
                             check=True, capture_output=True, text=True)
                logger.info("Attached %s to bridge", veth_pri_host)

            if "state UP" not in result.stdout:
                subprocess.run(["ip", "link", "set", veth_pri_host, "up"], check=True, capture_output=True, text=True)
                logger.info("Brought %s up", veth_pri_host)

        # Move veth peers into namespaces
        if not check_veth_in_netns(public_ns, veth_pub_ns):
            if check_veth_exists(veth_pub_ns):
                subprocess.run(["ip", "link", "set", veth_pub_ns, "netns", public_ns],
                             check=True, capture_output=True, text=True)
                logger.info("Moved %s into namespace %s", veth_pub_ns, public_ns)
            else:
                found_ns = find_interface_namespace(veth_pub_ns)
                if found_ns:
                    logger.warning("Peer %s found in namespace %s; will reuse", veth_pub_ns, found_ns)
                    public_ns = found_ns
                else:
                    logger.info("Peer %s not found", veth_pub_ns)

        if not check_veth_in_netns(private_ns, veth_pri_ns):
            if check_veth_exists(veth_pri_ns):
                subprocess.run(["ip", "link", "set", veth_pri_ns, "netns", private_ns],
                             check=True, capture_output=True, text=True)
                logger.info("Moved %s into namespace %s", veth_pri_ns, private_ns)
            else:
                found_ns = find_interface_namespace(veth_pri_ns)
                if found_ns:
                    logger.warning("Peer %s found in namespace %s; will reuse", veth_pri_ns, found_ns)
                    private_ns = found_ns
                else:
                    logger.info("Peer %s not found", veth_pri_ns)

    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to create/configure veth pairs: %s", stderr)
        return 1

    # Assign IPs to namespace interfaces
    try:
        pub_net = ipaddress.ip_network(public_subnet, strict=False)
        pri_net = ipaddress.ip_network(private_subnet, strict=False)
    except Exception as e:
        logger.error("Invalid public/private subnet CIDR: %s %s", public_subnet, private_subnet)
        return 1

    pub_hosts = list(pub_net.hosts())
    pri_hosts = list(pri_net.hosts())
    if not pub_hosts or not pri_hosts:
        logger.error("Public or private subnet has no usable hosts")
        return 1

    # Gateway IPs (first IP of each subnet) - assigned to bridge
    # Namespace IPs (second IP of each subnet)
    pub_gateway = pub_hosts[0] if len(pub_hosts) > 0 else None
    pri_gateway = pri_hosts[0] if len(pri_hosts) > 0 else None

    pub_ip = pub_hosts[1] if len(pub_hosts) > 1 else None
    pri_ip = pri_hosts[1] if len(pri_hosts) > 1 else None

    if pub_gateway is None or pri_gateway is None or pub_ip is None or pri_ip is None:
        logger.error("Subnets must have at least 2 usable host IPs each")
        return 1

    pub_gateway_str = f"{pub_gateway}/{pub_net.prefixlen}"
    pri_gateway_str = f"{pri_gateway}/{pri_net.prefixlen}"
    pub_ip_str = f"{pub_ip}/{pub_net.prefixlen}"
    pri_ip_str = f"{pri_ip}/{pri_net.prefixlen}"

    # Assign gateway IPs to bridge
    try:
        if not check_ip_on_interface(bridge_name, pub_gateway_str):
            subprocess.run(["ip", "addr", "add", pub_gateway_str, "dev", bridge_name],
                         check=True, capture_output=True, text=True)
            logger.info("Assigned public gateway %s to bridge", pub_gateway_str)
        else:
            logger.info("Public gateway IP %s already on bridge", pub_gateway_str)

        if not check_ip_on_interface(bridge_name, pri_gateway_str):
            subprocess.run(["ip", "addr", "add", pri_gateway_str, "dev", bridge_name],
                         check=True, capture_output=True, text=True)
            logger.info("Assigned private gateway %s to bridge", pri_gateway_str)
        else:
            logger.info("Private gateway IP %s already on bridge", pri_gateway_str)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to assign gateway IPs to bridge: %s", stderr)
        return 1

    # Configure namespace interfaces
    try:
        if not check_ip_in_netns(public_ns, veth_pub_ns, pub_ip_str):
            subprocess.run(["ip", "netns", "exec", public_ns, "ip", "addr", "add", pub_ip_str, "dev", veth_pub_ns],
                         check=True, capture_output=True, text=True)
            logger.info("Assigned %s to %s in %s", pub_ip_str, veth_pub_ns, public_ns)

        subprocess.run(["ip", "netns", "exec", public_ns, "ip", "link", "set", veth_pub_ns, "up"],
                     check=True, capture_output=True, text=True)
        subprocess.run(["ip", "netns", "exec", public_ns, "ip", "link", "set", "lo", "up"],
                     check=True, capture_output=True, text=True)

        if not check_ip_in_netns(private_ns, veth_pri_ns, pri_ip_str):
            subprocess.run(["ip", "netns", "exec", private_ns, "ip", "addr", "add", pri_ip_str, "dev", veth_pri_ns],
                         check=True, capture_output=True, text=True)
            logger.info("Assigned %s to %s in %s", pri_ip_str, veth_pri_ns, private_ns)

        subprocess.run(["ip", "netns", "exec", private_ns, "ip", "link", "set", veth_pri_ns, "up"],
                     check=True, capture_output=True, text=True)
        subprocess.run(["ip", "netns", "exec", private_ns, "ip", "link", "set", "lo", "up"],
                     check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to configure namespaces: %s", stderr)
        return 1

    # Configure routing
    try:
        logger.info("Configuring default routes in namespaces")

        def _add_default_route(ns: str, peer_if: str, gateway: str):
            if check_route_in_netns(ns, gateway):
                logger.info("Default route already exists in %s", ns)
                return

            if not check_veth_in_netns(ns, peer_if):
                logger.warning("Interface %s not in namespace %s; skipping route", peer_if, ns)
                return

            try:
                subprocess.run(["ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", gateway],
                             check=True, capture_output=True, text=True)
                logger.info("Set default route in %s via %s", ns, gateway)
            except subprocess.CalledProcessError as e:
                logger.warning("Failed to add default route in %s: %s", ns, str(e))

        _add_default_route(public_ns, veth_pub_ns, str(pub_gateway))
        _add_default_route(private_ns, veth_pri_ns, str(pri_gateway))

    except Exception as e:
        logger.error("Error setting default routes: %s", str(e))

    # Enable IP forwarding and NAT
    try:
        if not check_ip_forward_enabled():
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True, capture_output=True, text=True)
            logger.info("Enabled IP forwarding")

        if not check_iptables_rule_exists("nat", "POSTROUTING",
                                         ["-s", str(public_subnet), "-o", str(interface), "-j", "MASQUERADE"]):
            subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", str(public_subnet),
                          "-o", str(interface), "-j", "MASQUERADE"], check=True, capture_output=True, text=True)
            logger.info("Added NAT rule for public subnet")

    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to configure NAT: %s", stderr)
        return 1

    # Add FORWARD rules
    try:
        fwd_rules = [
            (["-i", str(interface), "-o", bridge_name, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"], "established connections"),
            (["-i", bridge_name, "-o", str(interface), "-j", "ACCEPT"], "bridge to interface"),
            (["-p", "tcp", "-d", str(public_subnet), "-m", "multiport", "--dports", "80,443,22", "-j", "ACCEPT"], "ports 80,443,22")
        ]

        for rule_args, desc in fwd_rules:
            if not check_iptables_rule_exists("filter", "FORWARD", rule_args):
                subprocess.run(["iptables", "-A", "FORWARD"] + rule_args, check=True, capture_output=True, text=True)
                logger.info("Added FORWARD rule for %s", desc)

    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to configure FORWARD rules: %s", stderr)
        return 1

    # Save metadata
    vpc_record = {
        "name": name,
        "bridge": bridge_name,
        "public_ns": public_ns,
        "private_ns": private_ns,
        "public_subnet": str(public_subnet),
        "private_subnet": str(private_subnet),
        "interface": str(interface),
        "bridge_ip": ip_str,
    }
    save_vpc_metadata(vpc_record)

    logger.info("Successfully created VPC %s", name)
    return 0


def list_vpcs(args: argparse.Namespace = None) -> int:
    """List all existing VPCs."""
    vpcs = load_vpc_metadata()

    if vpcs:
        print("Existing VPCs")
        print("--------------")
        for vpc in vpcs:
            print(vpc.get("name"))
        return 0

    # Fallback to bridge detection
    try:
        result = subprocess.run(["ip", "link", "show", "type", "bridge"], check=True, capture_output=True, text=True)
        vpc_pattern = re.compile(r'^\d+:\s+([a-zA-Z0-9_-]+):', re.MULTILINE)
        bridge_names = vpc_pattern.findall(result.stdout or "")
        if not bridge_names:
            print("No existing VPCs.")
            return 0
        print("Existing VPCs")
        print("--------------")
        for bridge in bridge_names:
            print(bridge)
        return 0
    except subprocess.CalledProcessError as e:
        logger.error("Failed to list VPCs: %s", str(e))
        return 1


def inspect_vpc(args: argparse.Namespace = None) -> int:
    """Show detailed information about a VPC."""
    vpc_name = str(getattr(args, "name"))
    if not vpc_name:
        logger.error("VPC name must be provided")
        return 1

    logger.info("Inspecting VPC %s", vpc_name)

    vpc_record = find_vpc_by_name(vpc_name)
    if vpc_record:
        print(f"{vpc_name} details\n")
        field_names = {
            "name": "Name",
            "bridge": "Bridge",
            "public_ns": "Public Namespace",
            "private_ns": "Private Namespace",
            "public_subnet": "Public Subnet",
            "private_subnet": "Private Subnet",
            "interface": "Interface",
            "bridge_ip": "Bridge IP",
        }
        for key, label in field_names.items():
            if vpc_record.get(key):
                print(f"{label}: {vpc_record[key]}\n")
        return 0

    logger.error("VPC named '%s' not found", vpc_name)
    return 1


def delete_vpc(args: argparse.Namespace = None) -> int:
    """Delete a VPC and all its resources."""
    vpc_name = str(getattr(args, "name"))
    if not vpc_name:
        logger.error("VPC name must be provided")
        return 1

    logger.info("Attempting to delete VPC %s", vpc_name)

    # Load VPC record
    record = find_vpc_by_name(vpc_name)

    # Derive resource names
    bridge_name = record.get("bridge") if record else "br-" + _short_hash(vpc_name, 11)
    public_ns = record.get("public_ns") if record else None
    private_ns = record.get("private_ns") if record else None
    interface = record.get("interface") if record else None
    public_subnet = record.get("public_subnet") if record else None

    veth_pub_host = "veth-" + _short_hash(vpc_name + "-pub-h", 10)
    veth_pri_host = "veth-" + _short_hash(vpc_name + "-pri-h", 10)

    # Remove iptables rules
    try:
        if interface and public_subnet:
            rules_to_remove = [
                ("nat", "POSTROUTING", ["-s", str(public_subnet), "-o", str(interface), "-j", "MASQUERADE"]),
                ("filter", "FORWARD", ["-i", str(interface), "-o", bridge_name, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]),
                ("filter", "FORWARD", ["-i", bridge_name, "-o", str(interface), "-j", "ACCEPT"]),
                ("filter", "FORWARD", ["-p", "tcp", "-d", str(public_subnet), "-m", "multiport", "--dports", "80,443,22", "-j", "ACCEPT"])
            ]

            for table, chain, rule_args in rules_to_remove:
                if check_iptables_rule_exists(table, chain, rule_args):
                    subprocess.run(["iptables", "-t", table, "-D", chain] + rule_args, check=True)
                    logger.info("Removed iptables rule from %s %s", table, chain)

    except subprocess.CalledProcessError as e:
        logger.warning("Some iptables removals failed: %s", str(e))

    # Delete namespaces
    for ns in (public_ns, private_ns):
        if ns and check_netns_exists(ns):
            try:
                subprocess.run(["ip", "netns", "delete", ns], check=True)
                logger.info("Deleted namespace %s", ns)
            except subprocess.CalledProcessError as e:
                logger.warning("Failed to delete namespace %s: %s", ns, str(e))

    # Delete veth interfaces
    for veth in (veth_pub_host, veth_pri_host):
        if check_veth_exists(veth):
            try:
                subprocess.run(["ip", "link", "delete", veth, "type", "veth"], check=True)
                logger.info("Deleted veth %s", veth)
            except subprocess.CalledProcessError as e:
                logger.warning("Failed to delete veth %s: %s", veth, str(e))

    # Delete bridge
    if check_bridge_exists(bridge_name):
        try:
            subprocess.run(["ip", "link", "delete", bridge_name, "type", "bridge"], check=True)
            logger.info("Deleted bridge %s", bridge_name)
        except subprocess.CalledProcessError as e:
            logger.warning("Failed to delete bridge %s: %s", bridge_name, str(e))

    # Remove metadata
    delete_vpc_metadata(vpc_name)

    logger.info("Finished deletion of VPC %s", vpc_name)
    return 0
