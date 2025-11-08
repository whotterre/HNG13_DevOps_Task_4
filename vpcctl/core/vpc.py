import argparse
from .utils import is_root, is_on_linux, get_hash
import logging
import subprocess
import ipaddress

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vpcctl.core.vpc")


def create_vpc(args: argparse.Namespace) -> int:
    """Create a VPC from parsed CLI args.

    Returns 0 on success, non-zero on failure. Supports an optional
    `args.dry_run` boolean to skip system changes for testing.
    """
    dry_run = getattr(args, "dry_run", False)

    # Validate arguments
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

    logger.info("Preparing to create VPC %s", name)

    if dry_run:
        logger.info("DRY-RUN: would create VPC with: name=%s cidr=%s public=%s private=%s interface=%s",
                    name, cidr, public_subnet, private_subnet, interface)
        return 0

    # Verify environment
    if not is_on_linux():
        logger.error("User can only run this script on a Linux based OS")
        return 1
    if not is_root():
        logger.error("User must be root to create a VPC")
        return 1

    # Create a network bridge.
    bridge_name = "net-" + get_hash(name)
    cmd = ["ip", "link", "add", bridge_name, "type", "bridge"]
    logger.info("Creating bridge with name %s", bridge_name)
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        logger.info("Successfully created bridge %s", bridge_name)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to create bridge: %s", stderr)
        return 1
    
    # Pick an IP address from the CIDR range and assign it to the bridge
    # Strategy:
    # - Use ipaddress to enumerate usable hosts
    # - Skip the first host (if requested by the original comment)
    # - Check `ip addr show` to ensure the chosen address is not already assigned
    # - Assign the address (ip addr add <ip>/<prefix> dev <bridge>) and bring bridge up

    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception as e:
        logger.error("Invalid CIDR provided: %s", cidr)
        return 1

    hosts = list(net.hosts())
    if not hosts:
        logger.error("CIDR %s has no usable addresses", cidr)
        return 1

    # Skip the first host to "Make sure it's not the first" per comment
    candidate_ips = hosts[1:] if len(hosts) > 1 else hosts

    # Get current addresses on the host so we can detect collisions
    try:
        ip_addr = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True, check=True).stdout
    except subprocess.CalledProcessError as e:
        logger.error("Failed to query local addresses: %s", e)
        return 1

    chosen_ip = None
    for ip in candidate_ips:
        # Search for "inet <ip>/" to detect assignment (ip addr shows 'inet 10.0.2.1/24')
        ip_with_prefix = f"{ip}/{net.prefixlen}"
        if ip_with_prefix in ip_addr:
            logger.debug("IP %s already present on host, skipping", ip_with_prefix)
            continue
        chosen_ip = ip
        break

    if chosen_ip is None:
        logger.error("No free IP addresses found in %s", cidr)
        return 1

    # Assign the chosen IP to the bridge and bring it up
    ip_str = f"{chosen_ip}/{net.prefixlen}"
    logger.info("Assigning IP %s to bridge %s", ip_str, bridge_name)
    if dry_run:
        logger.info("DRY-RUN: would run: ip addr add %s dev %s", ip_str, bridge_name)
        logger.info("DRY-RUN: would run: ip link set %s up", bridge_name)
        return 0

    try:
        subprocess.run(["ip", "addr", "add", ip_str, "dev", bridge_name], check=True, capture_output=True, text=True)
        subprocess.run(["ip", "link", "set", bridge_name, "up"], check=True, capture_output=True, text=True)
        logger.info("Assigned %s to %s and brought it up", ip_str, bridge_name)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to assign IP or bring bridge up: %s", stderr)
        return 1
    

    return 0
