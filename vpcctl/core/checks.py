"""
VPC validation and existence check utilities.
Provides idempotency checks for network resources.
"""
import subprocess
import logging

logger = logging.getLogger("vpcctl.core.checks")


def check_bridge_exists(bridge_name: str) -> bool:
    """Check if a bridge interface exists."""
    result = subprocess.run(["ip", "link", "show", bridge_name], capture_output=True, text=True)
    return result.returncode == 0


def check_netns_exists(ns_name: str) -> bool:
    """Check if a network namespace exists."""
    result = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
    return ns_name in result.stdout


def check_veth_exists(veth_name: str) -> bool:
    """Check if a veth interface exists in the host namespace."""
    result = subprocess.run(["ip", "link", "show", veth_name], capture_output=True, text=True)
    return result.returncode == 0


def check_veth_in_netns(ns_name: str, veth_name: str) -> bool:
    """Check if a veth interface exists in a specific network namespace."""
    result = subprocess.run(
        ["ip", "netns", "exec", ns_name, "ip", "link", "show", veth_name],
        capture_output=True,
        text=True
    )
    return result.returncode == 0


def find_interface_namespace(veth_name: str):
    """Return the namespace that currently contains veth_name or None."""
    r = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout:
        return None
    for ln in r.stdout.splitlines():
        ns_name = ln.split()[0]
        check_result = subprocess.run(
            ["ip", "netns", "exec", ns_name, "ip", "link", "show", veth_name],
            capture_output=True
        )
        if check_result.returncode == 0:
            return ns_name
    return None


def check_ip_on_interface(interface: str, ip_with_prefix: str) -> bool:
    """Check if an IP address is assigned to an interface in the host namespace."""
    result = subprocess.run(["ip", "addr", "show", "dev", interface], capture_output=True, text=True)
    return ip_with_prefix in result.stdout


def check_ip_in_netns(ns_name: str, veth_name: str, ip_with_prefix: str) -> bool:
    """Check if an IP address is assigned to an interface in a namespace."""
    result = subprocess.run(
        ["ip", "netns", "exec", ns_name, "ip", "addr", "show", "dev", veth_name],
        capture_output=True,
        text=True
    )
    return ip_with_prefix in result.stdout


def check_route_in_netns(ns_name: str, gateway_ip: str) -> bool:
    """Check if a default route via gateway_ip exists in a namespace."""
    result = subprocess.run(
        ["ip", "netns", "exec", ns_name, "ip", "route", "show"],
        capture_output=True,
        text=True
    )
    return f"default via {gateway_ip}" in result.stdout


def check_iptables_rule_exists(table: str, chain: str, rule_args: list) -> bool:
    """Check if an iptables rule exists."""
    check_cmd = ["iptables", "-t", table, "-C", chain] + rule_args
    result = subprocess.run(check_cmd, capture_output=True, text=True)
    return result.returncode == 0


def check_ip_forward_enabled() -> bool:
    """Check if IP forwarding is enabled."""
    result = subprocess.run(["sysctl", "-n", "net.ipv4.ip_forward"], capture_output=True, text=True)
    return result.stdout.strip() == "1"
