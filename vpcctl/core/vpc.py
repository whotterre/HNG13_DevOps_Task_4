import argparse
from .utils import is_root, is_on_linux, get_hash, get_rand_int
import logging
import subprocess
import ipaddress

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vpcctl.core.vpc")

def _short_hash(s: str, max_len: int) -> str:
    """
    Truncates long hashes to prevent kernel policy violaion (char count must be < 15)
    """
    h = get_hash(s)
    return h[:max_len]


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
    bridge_name = "net-" + _short_hash(name, 11)
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
    
    # Create network namespaces for the subnets
    try:
        private_ns = "vpc-pr-ns-" + _short_hash(name + str(get_rand_int(), 8))
        subprocess.run(["ip", "netns", "add", private_ns], check=True, capture_output=True, text=True)
        logger.info("Created network namespace for private subnet: %s", private_ns)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to create network namespace for private subnet: %s", stderr)
        return 1

    try:
        public_ns = "vpc-pub-ns-" + _short_hash(name + str(get_rand_int(), 8))
        subprocess.run(["ip", "netns", "add", public_ns], check=True, capture_output=True, text=True)
        logger.info("Created network namespace for public subnet: %s", public_ns)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to create network namespace for public subnet: %s", stderr)
        return 1

    # Create veth pairs for public and private namespaces, attach host ends to bridge,
    # move peer ends into their respective namespaces, then assign IPs and bring up links.
    try:
        veth_pub_host = "veth-" + _short_hash(name + "-pub-h", 10)
        veth_pub_ns = "veth-" + _short_hash(name + "-pub-n", 10)
        veth_pri_host = "veth-" + _short_hash(name + "-pri-h", 10)
        veth_pri_ns = "veth-" + _short_hash(name + "-pri-n", 10)

        # Create pairs
        subprocess.run(["ip", "link", "add", veth_pub_host, "type", "veth", "peer", "name", veth_pub_ns], check=True, capture_output=True, text=True)
        subprocess.run(["ip", "link", "add", veth_pri_host, "type", "veth", "peer", "name", veth_pri_ns], check=True, capture_output=True, text=True)

        # Attach host ends to bridge and bring them up
        subprocess.run(["ip", "link", "set", veth_pub_host, "master", bridge_name], check=True, capture_output=True, text=True)
        subprocess.run(["ip", "link", "set", veth_pri_host, "master", bridge_name], check=True, capture_output=True, text=True)
        subprocess.run(["ip", "link", "set", veth_pub_host, "up"], check=True, capture_output=True, text=True)
        subprocess.run(["ip", "link", "set", veth_pri_host, "up"], check=True, capture_output=True, text=True)

        # Move peer ends into namespaces
        subprocess.run(["ip", "link", "set", veth_pub_ns, "netns", public_ns], check=True, capture_output=True, text=True)
        subprocess.run(["ip", "link", "set", veth_pri_ns, "netns", private_ns], check=True, capture_output=True, text=True)

        logger.info("Connected namespaces to bridge using: %s<->%s and %s<->%s", veth_pub_host, veth_pub_ns, veth_pri_host, veth_pri_ns)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to create/move veth pairs: %s", stderr)
        return 1

    # Choose IPs for the namespace interfaces from their subnet CIDRs
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

    # Pick the first usable host in each subnet (avoid chosen_ip used on bridge)
    def pick_first(net_hosts, avoid_ip):
        for h in net_hosts:
            if str(h) == str(avoid_ip):
                continue
            return h
        return None

    pub_ip = pick_first(pub_hosts, chosen_ip)
    pri_ip = pick_first(pri_hosts, chosen_ip)
    if pub_ip is None or pri_ip is None:
        logger.error("Could not select namespace IPs that avoid the bridge IP")
        return 1

    pub_ip_str = f"{pub_ip}/{pub_net.prefixlen}"
    pri_ip_str = f"{pri_ip}/{pri_net.prefixlen}"

    # In dry-run, show the planned namespace configuration
    if dry_run:
        logger.info("DRY-RUN: would assign %s to %s inside namespace %s", pub_ip_str, veth_pub_ns, public_ns)
        logger.info("DRY-RUN: would bring up lo and %s inside %s", veth_pub_ns, public_ns)
        logger.info("DRY-RUN: would assign %s to %s inside namespace %s", pri_ip_str, veth_pri_ns, private_ns)
        logger.info("DRY-RUN: would bring up lo and %s inside %s", veth_pri_ns, private_ns)
        return 0

    # Assign IPs inside namespaces and bring up loopback + veth interfaces
    try:
        subprocess.run(["ip", "netns", "exec", public_ns, "ip", "addr", "add", pub_ip_str, "dev", veth_pub_ns], check=True, capture_output=True, text=True)
        subprocess.run(["ip", "netns", "exec", public_ns, "ip", "link", "set", veth_pub_ns, "up"], check=True, capture_output=True, text=True)
        subprocess.run(["ip", "netns", "exec", public_ns, "ip", "link", "set", "lo", "up"], check=True, capture_output=True, text=True)
        subprocess.run(["ip", "netns", "exec", private_ns, "ip", "addr", "add", pri_ip_str, "dev", veth_pri_ns], check=True, capture_output=True, text=True)
        subprocess.run(["ip", "netns", "exec", private_ns, "ip", "link", "set", veth_pri_ns, "up"], check=True, capture_output=True, text=True)
        subprocess.run(["ip", "netns", "exec", private_ns, "ip", "link", "set", "lo", "up"], check=True, capture_output=True, text=True)

        logger.info("Assigned namespace IPs and brought up loopback + veth interfaces")
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to configure namespaces: %s", stderr)
        return 1
    

    


    




    return 0
