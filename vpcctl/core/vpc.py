import argparse
import re
from .utils import is_root, is_on_linux, get_hash, get_rand_int
import logging
import subprocess
import ipaddress
import os
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vpcctl.core.vpc")

def _short_hash(s: str, max_len: int) -> str:
    h = get_hash(s)
    return h[:max_len]

# Idempotency checks
def _check_bridge_exists(bridge_name: str) -> bool:
    result = subprocess.run(["ip", "link", "show", bridge_name], capture_output=True, text=True)
    return result.returncode == 0


def _check_netns_exists(ns_name: str) -> bool:
    result = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
    return ns_name in result.stdout


def _check_veth_exists(veth_name: str) -> bool:
    result = subprocess.run(["ip", "link", "show", veth_name], capture_output=True, text=True)
    return result.returncode == 0


def _check_veth_in_netns(ns_name: str, veth_name: str) -> bool:
    result = subprocess.run(["ip", "netns", "exec", ns_name, "ip", "link", "show", veth_name], 
                          capture_output=True, text=True)
    return result.returncode == 0


def _find_interface_namespace(veth_name: str):
    """Return the namespace that currently contains veth_name or None."""
    r = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout:
        return None
    for ln in r.stdout.splitlines():
        ns_name = ln.split()[0]
        if subprocess.run(["ip", "netns", "exec", ns_name, "ip", "link", "show", veth_name], capture_output=True).returncode == 0:
            return ns_name
    return None


def _check_ip_on_interface(interface: str, ip_with_prefix: str) -> bool:
    result = subprocess.run(["ip", "addr", "show", "dev", interface], capture_output=True, text=True)
    return ip_with_prefix in result.stdout


def _check_ip_in_netns(ns_name: str, veth_name: str, ip_with_prefix: str) -> bool:
    result = subprocess.run(["ip", "netns", "exec", ns_name, "ip", "addr", "show", "dev", veth_name],
                          capture_output=True, text=True)
    return ip_with_prefix in result.stdout


def _check_route_in_netns(ns_name: str, gateway_ip: str) -> bool:
    result = subprocess.run(["ip", "netns", "exec", ns_name, "ip", "route", "show"], 
                          capture_output=True, text=True)
    return f"default via {gateway_ip}" in result.stdout


def _check_iptables_rule_exists(table: str, chain: str, rule_args: list) -> bool:
    check_cmd = ["iptables", "-t", table, "-C", chain] + rule_args
    result = subprocess.run(check_cmd, capture_output=True, text=True)
    return result.returncode == 0


def _check_ip_forward_enabled() -> bool:
    result = subprocess.run(["sysctl", "-n", "net.ipv4.ip_forward"], capture_output=True, text=True)
    return result.stdout.strip() == "1"


def create_vpc(args: argparse.Namespace) -> int:
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

    if not is_on_linux():
        logger.error("User can only run this script on a Linux based OS")
        return 1
    if not is_root():
        logger.error("User must be root to create a VPC")
        return 1

    bridge_name = "br-" + _short_hash(name, 11)

    try:
        if _check_bridge_exists(bridge_name):
            logger.info("Bridge %s already exists", bridge_name)
        else:
            logger.info("Creating bridge with name %s", bridge_name)
            subprocess.run(["ip", "link", "add", bridge_name, "type", "bridge"], check=True)
            logger.info("Successfully created bridge %s", bridge_name)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to create bridge: %s", stderr)
        return 1
    
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
        if _check_ip_on_interface(bridge_name, ip_with_prefix):
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
    
    if not _check_ip_on_interface(bridge_name, ip_str):
        logger.info("Assigning IP %s to bridge %s", ip_str, bridge_name)
        try:
            subprocess.run(["ip", "addr", "add", ip_str, "dev", bridge_name], check=True, capture_output=True, text=True)
            logger.info("Assigned %s to %s", ip_str, bridge_name)
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.strip() if e.stderr else str(e)
            logger.error("Failed to assign IP: %s", stderr)
            return 1

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
    
    private_ns = "vpc-pr-ns-" + _short_hash(name + str(get_rand_int()), 8)
    public_ns = "vpc-pub-ns-" + _short_hash(name + str(get_rand_int()), 8)

    try:
        if _check_netns_exists(private_ns):
            logger.info("Network namespace %s already exists", private_ns)
        else:
            subprocess.run(["ip", "netns", "add", private_ns], check=True, capture_output=True, text=True)
            logger.info("Created network namespace for private subnet: %s", private_ns)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to create network namespace for private subnet: %s", stderr)
        return 1

    try:
        if _check_netns_exists(public_ns):
            logger.info("Network namespace %s already exists", public_ns)
        else:
            subprocess.run(["ip", "netns", "add", public_ns], check=True, capture_output=True, text=True)
            logger.info("Created network namespace for public subnet: %s", public_ns)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to create network namespace for public subnet: %s", stderr)
        return 1

    veth_pub_host = "veth-" + _short_hash(name + "-pub-h", 10)
    veth_pub_ns = "veth-" + _short_hash(name + "-pub-n", 10)
    veth_pri_host = "veth-" + _short_hash(name + "-pri-h", 10)
    veth_pri_ns = "veth-" + _short_hash(name + "-pri-n", 10)

    try:
        if _check_veth_exists(veth_pub_host) or _check_veth_in_netns(public_ns, veth_pub_ns):
            logger.info("Public veth pair already exists")
        else:
            subprocess.run(["ip", "link", "add", veth_pub_host, "type", "veth", "peer", "name", veth_pub_ns], 
                         check=True, capture_output=True, text=True)
            logger.info("Created public veth pair: %s<->%s", veth_pub_host, veth_pub_ns)

        if _check_veth_exists(veth_pri_host) or _check_veth_in_netns(private_ns, veth_pri_ns):
            logger.info("Private veth pair already exists")
        else:
            subprocess.run(["ip", "link", "add", veth_pri_host, "type", "veth", "peer", "name", veth_pri_ns], 
                         check=True, capture_output=True, text=True)
            logger.info("Created private veth pair: %s<->%s", veth_pri_host, veth_pri_ns)

        if _check_veth_exists(veth_pub_host):
            result = subprocess.run(["ip", "link", "show", veth_pub_host], capture_output=True, text=True)
            if f"master {bridge_name}" not in result.stdout:
                subprocess.run(["ip", "link", "set", veth_pub_host, "master", bridge_name], 
                             check=True, capture_output=True, text=True)
                logger.info("Attached %s to bridge", veth_pub_host)
            
            if "state UP" not in result.stdout:
                subprocess.run(["ip", "link", "set", veth_pub_host, "up"], check=True, capture_output=True, text=True)
                logger.info("Brought %s up", veth_pub_host)

        if _check_veth_exists(veth_pri_host):
            result = subprocess.run(["ip", "link", "show", veth_pri_host], capture_output=True, text=True)
            if f"master {bridge_name}" not in result.stdout:
                subprocess.run(["ip", "link", "set", veth_pri_host, "master", bridge_name], 
                             check=True, capture_output=True, text=True)
                logger.info("Attached %s to bridge", veth_pri_host)
            
            if "state UP" not in result.stdout:
                subprocess.run(["ip", "link", "set", veth_pri_host, "up"], check=True, capture_output=True, text=True)
                logger.info("Brought %s up", veth_pri_host)

        if not _check_veth_in_netns(public_ns, veth_pub_ns):
            if _check_veth_exists(veth_pub_ns):
                subprocess.run(["ip", "link", "set", veth_pub_ns, "netns", public_ns], 
                             check=True, capture_output=True, text=True)
                logger.info("Moved %s into namespace %s", veth_pub_ns, public_ns)
            else:
                # If the peer isn't present on the host, see if it already lives in another namespace
                found_ns = _find_interface_namespace(veth_pub_ns)
                if found_ns:
                    logger.warning("Peer %s not on host but found in namespace %s; will reuse that namespace for configuration", veth_pub_ns, found_ns)
                    public_ns = found_ns
                else:
                    logger.info("Peer %s not present on host or in any namespace; cannot move into %s", veth_pub_ns, public_ns)

        if not _check_veth_in_netns(private_ns, veth_pri_ns):
            if _check_veth_exists(veth_pri_ns):
                subprocess.run(["ip", "link", "set", veth_pri_ns, "netns", private_ns], 
                             check=True, capture_output=True, text=True)
                logger.info("Moved %s into namespace %s", veth_pri_ns, private_ns)
            else:
                found_ns = _find_interface_namespace(veth_pri_ns)
                if found_ns:
                    logger.warning("Peer %s not on host but found in namespace %s; will reuse that namespace for configuration", veth_pri_ns, found_ns)
                    private_ns = found_ns
                else:
                    logger.info("Peer %s not present on host or in any namespace; cannot move into %s", veth_pri_ns, private_ns)

    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to create/configure veth pairs: %s", stderr)
        return 1

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

    try:
        if not _check_ip_in_netns(public_ns, veth_pub_ns, pub_ip_str):
            subprocess.run(["ip", "netns", "exec", public_ns, "ip", "addr", "add", pub_ip_str, "dev", veth_pub_ns], 
                         check=True, capture_output=True, text=True)
            logger.info("Assigned %s to %s in namespace %s", pub_ip_str, veth_pub_ns, public_ns)
        else:
            logger.info("IP %s already assigned in namespace %s", pub_ip_str, public_ns)

        result = subprocess.run(["ip", "netns", "exec", public_ns, "ip", "link", "show", veth_pub_ns], 
                              capture_output=True, text=True)
        if "state UP" not in result.stdout:
            subprocess.run(["ip", "netns", "exec", public_ns, "ip", "link", "set", veth_pub_ns, "up"], 
                         check=True, capture_output=True, text=True)
            logger.info("Brought up %s in namespace %s", veth_pub_ns, public_ns)

        result = subprocess.run(["ip", "netns", "exec", public_ns, "ip", "link", "show", "lo"], 
                              capture_output=True, text=True)
        if "state UNKNOWN" not in result.stdout and "state UP" not in result.stdout:
            subprocess.run(["ip", "netns", "exec", public_ns, "ip", "link", "set", "lo", "up"], 
                         check=True, capture_output=True, text=True)

        if not _check_ip_in_netns(private_ns, veth_pri_ns, pri_ip_str):
            subprocess.run(["ip", "netns", "exec", private_ns, "ip", "addr", "add", pri_ip_str, "dev", veth_pri_ns], 
                         check=True, capture_output=True, text=True)
            logger.info("Assigned %s to %s in namespace %s", pri_ip_str, veth_pri_ns, private_ns)
        else:
            logger.info("IP %s already assigned in namespace %s", pri_ip_str, private_ns)

        result = subprocess.run(["ip", "netns", "exec", private_ns, "ip", "link", "show", veth_pri_ns], 
                              capture_output=True, text=True)
        if "state UP" not in result.stdout:
            subprocess.run(["ip", "netns", "exec", private_ns, "ip", "link", "set", veth_pri_ns, "up"], 
                         check=True, capture_output=True, text=True)
            logger.info("Brought up %s in namespace %s", veth_pri_ns, private_ns)

        result = subprocess.run(["ip", "netns", "exec", private_ns, "ip", "link", "show", "lo"], 
                              capture_output=True, text=True)
        if "state UNKNOWN" not in result.stdout and "state UP" not in result.stdout:
            subprocess.run(["ip", "netns", "exec", private_ns, "ip", "link", "set", "lo", "up"], 
                         check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to configure namespaces: %s", stderr)
        return 1
    
    try:
        logger.info("Configuring default routes in namespaces")

        def _maybe_add_default(ns: str, peer_if: str):
            # If default already exists via chosen_ip, skip
            if _check_route_in_netns(ns, str(chosen_ip)):
                logger.info("Default route already exists in %s", ns)
                return

            # Ensure interface is present
            if not _check_veth_in_netns(ns, peer_if):
                logger.warning("Expected interface %s not present in namespace %s; skipping default route setup", peer_if, ns)
                return

            # First attempt: add default via gateway
            add_cmd = ["ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", str(chosen_ip)]
            try:
                subprocess.run(add_cmd, check=True, capture_output=True, text=True)
                logger.info("Set default route in %s via %s", ns, chosen_ip)
                return
            except subprocess.CalledProcessError as e:
                out = (e.stderr or e.stdout or "").strip()
                logger.warning("Failed to add default via %s in %s: %s", chosen_ip, ns, out)

            # If adding via gateway failed due to gateway not on-link, add a host route to gateway via the device
            gw_route_cmd = ["ip", "netns", "exec", ns, "ip", "route", "add", str(chosen_ip), "dev", peer_if]
            try:
                subprocess.run(gw_route_cmd, check=True, capture_output=True, text=True)
                logger.info("Added route to gateway %s dev %s in %s", chosen_ip, peer_if, ns)
            except subprocess.CalledProcessError:
                logger.warning("Could not add host route to gateway %s in %s; will try dev-only default", chosen_ip, ns)

            # Try adding default via gateway again
            try:
                subprocess.run(add_cmd, check=True, capture_output=True, text=True)
                logger.info("Set default route in %s via %s after adding host route", ns, chosen_ip)
                return
            except subprocess.CalledProcessError as e2:
                out2 = (e2.stderr or e2.stdout or "").strip()
                logger.warning("Second attempt to add default via %s failed in %s: %s", chosen_ip, ns, out2)

            # As a last resort, add a dev-only default route
            dev_default_cmd = ["ip", "netns", "exec", ns, "ip", "route", "add", "default", "dev", peer_if]
            try:
                subprocess.run(dev_default_cmd, check=True, capture_output=True, text=True)
                logger.info("Added dev-only default route in %s via dev %s", ns, peer_if)
                return
            except subprocess.CalledProcessError as e3:
                out3 = (e3.stderr or e3.stdout or "").strip()
                logger.warning("Failed to add dev-only default in %s: %s", ns, out3)

            logger.error("Unable to configure a default route in %s; manual intervention may be required", ns)

        # Map namespace to its peer interface name
        _maybe_add_default(public_ns, veth_pub_ns)
        _maybe_add_default(private_ns, veth_pri_ns)

    except Exception as e:
        logger.error("Unexpected error while setting default routes: %s", str(e))
        # don't abort the entire create for route problems; log and continue
        pass

    try:
        if not _check_ip_forward_enabled():
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True, capture_output=True, text=True)
            logger.info("Enabled IP forwarding")
        else:
            logger.info("IP forwarding already enabled")

        if not _check_iptables_rule_exists("nat", "POSTROUTING", 
                                          ["-s", str(public_subnet), "-o", str(interface), "-j", "MASQUERADE"]):
            subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", str(public_subnet), 
                          "-o", str(interface), "-j", "MASQUERADE"], check=True, capture_output=True, text=True)
            logger.info("Added NAT rule for public subnet")
        else:
            logger.info("NAT rule already exists for public subnet")

    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to enable IP forwarding: %s", stderr)
        return 1
    
    try:
        iface = str(interface)
        pub_sub = str(public_subnet)

        if not _check_iptables_rule_exists("filter", "FORWARD", 
                                          ["-i", iface, "-o", bridge_name, "-m", "conntrack", 
                                           "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]):
            subprocess.run(["iptables", "-A", "FORWARD", "-i", iface, "-o", bridge_name, 
                          "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"], 
                         check=True, capture_output=True, text=True)
            logger.info("Added FORWARD rule for established connections")
        else:
            logger.info("FORWARD rule for established connections already exists")

        if not _check_iptables_rule_exists("filter", "FORWARD", 
                                          ["-i", bridge_name, "-o", iface, "-j", "ACCEPT"]):
            subprocess.run(["iptables", "-A", "FORWARD", "-i", bridge_name, "-o", iface, "-j", "ACCEPT"], 
                         check=True, capture_output=True, text=True)
            logger.info("Added FORWARD rule from bridge to interface")
        else:
            logger.info("FORWARD rule from bridge to interface already exists")

        if not _check_iptables_rule_exists("filter", "FORWARD", 
                                          ["-p", "tcp", "-d", pub_sub, "-m", "multiport", 
                                           "--dports", "80,443,22", "-j", "ACCEPT"]):
            subprocess.run(["iptables", "-A", "FORWARD", "-p", "tcp", "-d", pub_sub, 
                          "-m", "multiport", "--dports", "80,443,22", "-j", "ACCEPT"], 
                         check=True, capture_output=True, text=True)
            logger.info("Added FORWARD rule for ports 80,443,22")
        else:
            logger.info("FORWARD rule for ports 80,443,22 already exists")

    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to configure FORWARD rules: %s", stderr)
        return 1

    file_dir = "/var/lib/vpcctl"
    file_name = os.path.join(file_dir, "vpcs.ndjson")
    try:
        os.makedirs(file_dir, exist_ok=True)
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
        with open(file_name, "a", encoding="utf-8") as f:
            f.write(json.dumps(vpc_record) + "\n")
        logger.info("Stored VPC metadata to %s", file_name)
    except Exception as e:
        logger.warning("Unable to persist VPC metadata to %s: %s", file_name, str(e))

    logger.info("Successfully created VPC %s", name)

    return 0

def list_vpcs(args: argparse.Namespace = None) -> int:
    """Lists existing VPCs

    Accepts an optional argparse.Namespace to match the CLI handler signature.
    """
    file_path = "/var/lib/vpcctl/vpcs.ndjson"
    try:
        names = []
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln:
                        continue
                    try:
                        rec = json.loads(ln)
                        nm = rec.get("name")
                        if nm:
                            names.append(nm)
                    except Exception:
                        logger.warning("Skipping malformed VPC record in %s", file_path)

        if names:
            print("Existing VPCs")
            print("--------------")
            for n in names:
                print(n)
            return 0

        result = subprocess.run(["ip", "link", "show", "type", "bridge"], check=True, capture_output=True, text=True)
        vpc_pattern = re.compile(r'^\d+:\s+([a-zA-Z0-9_-]+):', re.MULTILINE)
        vpcs = vpc_pattern.findall(result.stdout or "")
        if not vpcs:
            print("No existing VPCs.")
            return 0
        print("Existing VPCs")
        print("--------------")
        for vpc in list(vpcs):
            print(vpc)
        return 0
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to fetch list of existing VPCs: %s", stderr)
        return 1
    except Exception as e:
        logger.error("Unexpected error while listing VPCs: %s", str(e))
        return 1

def inspect_vpc(args: argparse.Namespace = None) -> int:
    """
    Shows information about an existing VPC 
    <vpc_name> - name of the VPC you want to spy on
    """
    
    # Ensure name argument is passed
    vpc_name = str(getattr(args, "name"))
    if not vpc_name:
       logger.error("VPC name must be passed as an argument. Try vpcctl inspect <vpc_name>")
       return 1
    
    try:
        logger.info("Inspecting VPC %s\n", vpc_name)
        vpc_list_file_path = "/var/lib/vpcctl/vpcs.ndjson"

        if os.path.exists(vpc_list_file_path):
            with open(vpc_list_file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        logger.warning("Skipping malformed VPC record in %s", vpc_list_file_path)
                        continue

                    if rec.get("name") == vpc_name:
                        print(f"{vpc_name} details \n")
                        deet_dict = {
                            "name": "Name",
                            "bridge": "Bridge",
                            "public_ns": "Public Namespace",
                            "private_ns": "Private Namespace",
                            "public_subnet":  "Public Subnet",
                            "private_subnet": "Private Subnet",
                            "interface": "Interface",
                             "bridge_ip": "Bridge IP",
                            }
                        for key, val in deet_dict.items():
                            if rec.get(key):
                               print(f"{val}: {rec[key]}\n")
                    
                        return 0

        result = subprocess.run(["ip", "link", "show", "type", "bridge"], check=True, capture_output=True, text=True)
        vpc_pattern = re.compile(r'^\d+:\s+([a-zA-Z0-9_-]+):', re.MULTILINE)
        vpcs = vpc_pattern.findall(result.stdout or "")
        if vpc_name in vpcs:
            bridge_out = subprocess.run(["ip", "link", "show", vpc_name], check=True, capture_output=True, text=True)
            print(bridge_out.stdout)
            return 0

        logger.error("VPC named '%s' not found", vpc_name)
        return 1
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Command failed while inspecting VPC: %s", stderr)
        return 1
    except Exception:
        logger.exception("Unexpected error while inspecting VPC %s", vpc_name)
        return 1
    
def delete_vpc(args: argparse.Namespace = None) -> int:
    """Deletes a VPC with specified name"""
    vpc_name = str(getattr(args, "name"))
    if not vpc_name:
       logger.error("VPC name must be passed as an argument. Try vpcctl delete <vpc_name>")
       return 1
    logger.info("Attempting to delete VPC %s", vpc_name)

    # Load the persisted record so we can target exact names
    vpc_list_file_path = "/var/lib/vpcctl/vpcs.ndjson"
    record = None
    try:
        if os.path.exists(vpc_list_file_path):
            with open(vpc_list_file_path, "r", encoding="utf-8") as f:
                for line in f:
                    stripped_line = line.strip()
                    if not stripped_line:
                        continue
                    try:
                        obj = json.loads(stripped_line)
                    except Exception:
                        continue
                    if obj.get("name") == vpc_name:
                        record = obj
                        break
    except Exception as e:
        logger.warning("Failed to read persisted VPC metadata: %s", str(e))

    # Derive names/values: prefer persisted record, fallback to deterministic names
    bridge_name = record.get("bridge") if record and record.get("bridge") else "br-" + _short_hash(vpc_name, 11)
    public_ns = record.get("public_ns") if record and record.get("public_ns") else None
    private_ns = record.get("private_ns") if record and record.get("private_ns") else None
    interface = record.get("interface") if record and record.get("interface") else None
    public_subnet = record.get("public_subnet") if record and record.get("public_subnet") else None

    # Host-side veth names are deterministic from creation code
    veth_pub_host = "veth-" + _short_hash(vpc_name + "-pub-h", 10)
    veth_pri_host = "veth-" + _short_hash(vpc_name + "-pri-h", 10)

    # Remove iptables rules that were added during creation
    try:
        if interface and public_subnet:
            # NAT rule
            nat_rule = ["-s", str(public_subnet), "-o", str(interface), "-j", "MASQUERADE"]
            if _check_iptables_rule_exists("nat", "POSTROUTING", nat_rule):
                subprocess.run(["iptables", "-t", "nat", "-D", "POSTROUTING"] + nat_rule, check=True)
                logger.info("Removed NAT POSTROUTING rule for %s via %s", public_subnet, interface)

            # FORWARD rules (best-effort removals)
            fwd1 = ["-i", str(interface), "-o", bridge_name, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]
            if _check_iptables_rule_exists("filter", "FORWARD", fwd1):
                subprocess.run(["iptables", "-D", "FORWARD"] + fwd1, check=True)
                logger.info("Removed FORWARD rule for established connections")

            fwd2 = ["-i", bridge_name, "-o", str(interface), "-j", "ACCEPT"]
            if _check_iptables_rule_exists("filter", "FORWARD", fwd2):
                subprocess.run(["iptables", "-D", "FORWARD"] + fwd2, check=True)
                logger.info("Removed FORWARD rule from bridge to interface")

            fwd3 = ["-p", "tcp", "-d", str(public_subnet), "-m", "multiport", "--dports", "80,443,22", "-j", "ACCEPT"]
            if _check_iptables_rule_exists("filter", "FORWARD", fwd3):
                subprocess.run(["iptables", "-D", "FORWARD"] + fwd3, check=True)
                logger.info("Removed FORWARD rule for ports 80,443,22")
    except subprocess.CalledProcessError as e:
        logger.warning("Some iptables removals failed: %s", str(e))

    # Delete network namespaces (if present)
    for ns in (public_ns, private_ns):
        if not ns:
            continue
        try:
            if _check_netns_exists(ns):
                subprocess.run(["ip", "netns", "delete", ns], check=True)
                logger.info("Deleted network namespace %s", ns)
            else:
                logger.debug("Network namespace %s not present", ns)
        except subprocess.CalledProcessError as e:
            logger.warning("Failed to delete netns %s: %s", ns, str(e))

    # Delete host veth interfaces if they exist
    for vh in (veth_pub_host, veth_pri_host):
        try:
            if _check_veth_exists(vh):
                subprocess.run(["ip", "link", "delete", vh, "type", "veth"], check=True)
                logger.info("Deleted veth %s", vh)
            else:
                logger.debug("Veth %s not present on host", vh)
        except subprocess.CalledProcessError as e:
            logger.warning("Failed to delete veth %s: %s", vh, str(e))

    # Delete bridge if present
    try:
        if _check_bridge_exists(bridge_name):
            subprocess.run(["ip", "link", "delete", bridge_name, "type", "bridge"], check=True)
            logger.info("Deleted bridge %s", bridge_name)
        else:
            logger.debug("Bridge %s not present", bridge_name)
    except subprocess.CalledProcessError as e:
        logger.warning("Failed to delete bridge %s: %s", bridge_name, str(e))

    # Remove persisted NDJSON entry (write back all records except the matching one)
    try:
        if os.path.exists(vpc_list_file_path):
            kept = []
            with open(vpc_list_file_path, "r", encoding="utf-8") as f:
                for line in f:
                    stripped_line = line.strip()
                    if not stripped_line:
                        continue
                    try:
                        obj = json.loads(stripped_line)
                    except Exception:
                        # keep malformed lines as-is to avoid accidental loss
                        kept.append(line)
                        continue
                    if obj.get("name") != vpc_name:
                        kept.append(line)

            # Atomic replace
            tmp_path = vpc_list_file_path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as out:
                out.writelines(kept)
            os.replace(tmp_path, vpc_list_file_path)
            logger.info("Removed VPC record %s from %s", vpc_name, vpc_list_file_path)
    except Exception as e:
        logger.warning("Failed to update persisted VPC metadata: %s", str(e))

    logger.info("Finished deletion attempt for VPC %s", vpc_name)
    return 0