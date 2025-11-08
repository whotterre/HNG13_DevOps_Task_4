import argparse
import sys
# Support both package-style execution (python -m vpcctl.cli) which uses
# relative imports, and direct script execution (python cli.py) which does
# not have a parent package. Try the relative import first, fall back to a
# local absolute import when running as a script from the `vpcctl` directory.
try:
    from .core import vpc
except Exception:
    # Running `python cli.py` inside the vpcctl/ directory: import core directly
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

    args = parser.parse_args()
    if hasattr(args, "func"):
        # Call the subcommand handler. Handlers should return an int exit code (0 success), or None.
        rc = args.func(args)
        return 0 if rc is None else rc

    parser.print_help()
    return 1


if __name__ == '__main__':
    sys.exit(main())