"""
VPC management core module.
Exports all VPC operations from modular components.
"""
import logging

# Import all public functions from submodules
from .lifecycle import create_vpc, list_vpcs, inspect_vpc, delete_vpc
from .peering import peer_vpcs, unpeer_vpcs
from .firewall import apply_policy

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vpcctl.core.vpc")

# Public API
__all__ = [
    'create_vpc',
    'list_vpcs',
    'inspect_vpc',
    'delete_vpc',
    'peer_vpcs',
    'unpeer_vpcs',
    'apply_policy'
]
