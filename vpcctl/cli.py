import argparse
import sys
try:
    from .core import vpc
except Exception:
    from core import vpc


def main():
    parser = argparse.ArgumentParser(
        prog="vpcctl",
        description="Manages mini virtual private clouds (VPCs) on Linux"
    )

    subparsers = parser.add_subparsers(
        title="Commands",
        dest="command"
    )
    # Create command - vpcctl create
    create_parser = subparsers.add_parser(
        "create",
        help="Creates a new VPC with base CIDR and subnets"
    )

    create_parser.add_argument("--name", required=True, help="Unique VPC name")
    create_parser.add_argument("--cidr", required=True, help="CIDR block (eg 10.0.0.0/16)")
    create_parser.add_argument("--public-subnet", required=True, help="Public subnet CIDR block (10.0.2.0/24)")
    create_parser.add_argument("--private-subnet", required=True, help="Private subnet CIDR block (e.g, 10.0.2.0/24)")
    create_parser.add_argument("--interface", required=True, help="Host's outbound network interface")
    create_parser.add_argument("--dry-run", action="store_true", help="Show planned actions without making system changes")
    create_parser.set_defaults(func=vpc.create_vpc)
    
    # list command - vpcctl list
    list_parser = subparsers.add_parser(
        "list",
        help="Lists existing VPCs"
    )
    list_parser.set_defaults(func=vpc.list_vpcs)

    # inspect command - vpcctl inspect <name>
    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Displays detailed info for one VPC — kinda like `aws ec2 describe-vpcs.`"
    )
    inspect_parser.add_argument("--name", required=True, help="Unique VPC name")
    inspect_parser.set_defaults(func=vpc.inspect_vpc)
    
    # delete command - vpcctl delete
    delete_parser = subparsers.add_parser(
        "delete",
        help="Deletes a VPC"
    )
    delete_parser.add_argument("--name", required=True, help="Unique VPC name")
    delete_parser.set_defaults(func=vpc.delete_vpc)
    
    # peer command - vpcctl peer
    peer_parser = subparsers.add_parser(
        "peer",
        help="Peer two VPCs by connecting their bridges and adding static routes"
    )
    peer_parser.add_argument("--vpc1", required=True, help="First VPC name")
    peer_parser.add_argument("--vpc2", required=True, help="Second VPC name")
    peer_parser.add_argument("--dry-run", action="store_true", help="Show planned actions without making system changes")
    peer_parser.set_defaults(func=vpc.peer_vpcs)
    
    # unpeer command - vpcctl unpeer
    unpeer_parser = subparsers.add_parser(
        "unpeer",
        help="Remove peering between two VPCs"
    )
    unpeer_parser.add_argument("--vpc1", required=True, help="First VPC name")
    unpeer_parser.add_argument("--vpc2", required=True, help="Second VPC name")
    unpeer_parser.add_argument("--dry-run", action="store_true", help="Show planned actions without making system changes")
    unpeer_parser.set_defaults(func=vpc.unpeer_vpcs)
    
    # apply-policy command - vpcctl apply-policy
    apply_policy_parser = subparsers.add_parser(
        "apply-policy",
        help="Apply firewall policy rules to a VPC subnet from a JSON file"
    )
    apply_policy_parser.add_argument("--name", required=True, help="VPC name")
    apply_policy_parser.add_argument("--subnet", required=True, choices=['public', 'private'], help="Subnet type (public or private)")
    apply_policy_parser.add_argument("--policy", required=True, help="Path to policy JSON file")
    apply_policy_parser.add_argument("--dry-run", action="store_true", help="Show planned actions without making system changes")
    apply_policy_parser.set_defaults(func=vpc.apply_policy)
    
    
    args = parser.parse_args()
    if hasattr(args, "func"):
        return_code = args.func(args)
        return 0 if return_code is None else return_code
    
  
    
    return 1


if __name__ == '__main__':
    sys.exit(main())