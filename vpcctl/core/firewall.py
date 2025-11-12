"""
VPC firewall policy management: apply security rules to VPC namespaces.
"""
import argparse
import subprocess
import json
import os
import logging

from .checks import check_netns_exists
from .metadata import find_vpc_by_name

logger = logging.getLogger("vpcctl.core.firewall")


def apply_policy(args: argparse.Namespace = None) -> int:
    """
    Apply firewall policy rules to a VPC namespace from a JSON policy file.
    
    Supports two policy formats:
    
    New format (ingress-based):
    {
        "subnet": "10.0.1.0/24",
        "ingress": [
            {"port": 80, "protocol": "tcp", "action": "allow"},
            {"port": 22, "protocol": "tcp", "action": "deny"}
        ]
    }
    
    Legacy format:
    {
        "version": "1.0",
        "default_policy": "DROP",
        "rules": [
            {"action": "ACCEPT", "protocol": "tcp", "port": 80}
        ]
    }
    """
    if args is None:
        logger.error("No arguments provided to apply_policy")
        return 1
    
    vpc_name = args.name
    subnet_type = args.subnet
    policy_file = args.policy
    dry_run = getattr(args, 'dry_run', False)
    
    if not vpc_name or not subnet_type or not policy_file:
        logger.error("--name, --subnet, and --policy are required")
        return 1
    
    if subnet_type not in ['public', 'private']:
        logger.error("--subnet must be 'public' or 'private'")
        return 1
    
    logger.info("Applying firewall policy to %s subnet of VPC %s", subnet_type, vpc_name)
    
    # Load policy file
    try:
        with open(policy_file, 'r', encoding='utf-8') as f:
            policy = json.load(f)
    except FileNotFoundError:
        logger.error("Policy file not found: %s", policy_file)
        return 1
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON in policy file: %s", str(e))
        return 1
    
    # Detect policy format and normalize to internal format
    rules = []
    default_policy = "ACCEPT"
    
    if 'ingress' in policy:
        # New format: {"subnet": "...", "ingress": [...]}
        logger.info("Detected new policy format with 'ingress' rules")
        default_policy = "ACCEPT"  # Default to accept, only block what's explicitly denied
        
        for rule in policy.get('ingress', []):
            action = rule.get('action', 'allow').lower()
            # Convert 'allow'/'deny' to 'ACCEPT'/'DROP'
            if action == 'allow':
                iptables_action = 'ACCEPT'
            elif action == 'deny':
                iptables_action = 'DROP'
            else:
                logger.warning("Unknown action '%s', skipping rule", action)
                continue
            
            rules.append({
                'action': iptables_action,
                'protocol': rule.get('protocol', 'tcp'),
                'port': rule.get('port'),
                'source': rule.get('source', '0.0.0.0/0'),
                'description': f"{action} {rule.get('protocol', 'tcp')}/{rule.get('port', 'any')}"
            })
    
    elif 'rules' in policy:
        # Legacy format: {"version": "...", "default_policy": "...", "rules": [...]}
        logger.info("Detected legacy policy format with 'rules' array")
        default_policy = policy.get('default_policy', 'ACCEPT').upper()
        if default_policy not in ['ACCEPT', 'DROP']:
            logger.error("default_policy must be 'ACCEPT' or 'DROP'")
            return 1
        rules = policy['rules']
    
    else:
        logger.error("Policy file must contain either 'ingress' or 'rules' array")
        return 1
    
    # Load VPC metadata
    vpc_record = find_vpc_by_name(vpc_name)
    
    if not vpc_record:
        logger.error("VPC %s not found", vpc_name)
        return 1
    
    # Get namespace for specified subnet
    if subnet_type == 'public':
        namespace = vpc_record.get('public_ns')
    else:
        namespace = vpc_record.get('private_ns')
    
    if not namespace:
        logger.error("Namespace for %s subnet not found in VPC metadata", subnet_type)
        return 1
    
    if not check_netns_exists(namespace):
        logger.error("Namespace %s does not exist", namespace)
        return 1
    
    if dry_run:
        logger.info("[DRY RUN] Would flush existing rules in namespace %s", namespace)
        logger.info("[DRY RUN] Would set default INPUT policy to %s", default_policy)
        for rule in rules:
            logger.info("[DRY RUN] Would add rule: %s", rule.get('description', str(rule)))
        return 0
    
    # Apply firewall rules
    try:
        # Flush existing INPUT rules
        logger.info("Flushing existing INPUT rules in namespace %s", namespace)
        subprocess.run(["ip", "netns", "exec", namespace, "iptables", "-F", "INPUT"],
                      check=True, capture_output=True, text=True)
        
        # Set default policy
        logger.info("Setting default INPUT policy to %s in namespace %s", default_policy, namespace)
        subprocess.run(["ip", "netns", "exec", namespace, "iptables", "-P", "INPUT", default_policy],
                      check=True, capture_output=True, text=True)
        
        # Always allow established/related connections
        subprocess.run(["ip", "netns", "exec", namespace, "iptables", "-A", "INPUT",
                       "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                      check=True, capture_output=True, text=True)
        logger.info("Added rule to accept ESTABLISHED,RELATED connections")
        
        # Always allow loopback traffic
        subprocess.run(["ip", "netns", "exec", namespace, "iptables", "-A", "INPUT",
                       "-i", "lo", "-j", "ACCEPT"],
                      check=True, capture_output=True, text=True)
        logger.info("Added rule to accept loopback traffic")
        
        # Apply custom rules
        for idx, rule in enumerate(rules):
            action = rule.get('action', 'ACCEPT').upper()
            if action not in ['ACCEPT', 'DROP', 'REJECT']:
                logger.warning("Invalid action '%s' in rule %d, skipping", action, idx)
                continue
            
            protocol = rule.get('protocol', '').lower()
            port = rule.get('port')
            source = rule.get('source', '0.0.0.0/0')
            description = rule.get('description', f'Rule {idx}')
            
            cmd = ["ip", "netns", "exec", namespace, "iptables", "-A", "INPUT"]
            
            if source and source != '0.0.0.0/0':
                cmd.extend(["-s", source])
            
            if protocol:
                cmd.extend(["-p", protocol])
                
                if port and protocol in ['tcp', 'udp']:
                    cmd.extend(["--dport", str(port)])
            
            cmd.extend(["-j", action])
            
            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True)
                logger.info("Added rule: %s (%s)", description, ' '.join(cmd[5:]))
            except subprocess.CalledProcessError as e:
                stderr = e.stderr.strip() if e.stderr else str(e)
                logger.warning("Failed to add rule '%s': %s", description, stderr)
        
        logger.info("Successfully applied firewall policy to %s subnet of VPC %s", subnet_type, vpc_name)
        return 0
        
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else str(e)
        logger.error("Failed to apply firewall policy: %s", stderr)
        return 1
    except Exception as e:
        logger.error("Unexpected error applying policy: %s", str(e))
        return 1
