#!/usr/bin/env bash
# Cleanup helper for vpcctl-created resources
# Usage:
#   sudo ./cleanup.sh --all            # delete all persisted VPCs
#   sudo ./cleanup.sh my-vpc           # delete specific VPC(s)
#   sudo ./cleanup.sh --dry-run --all  # show what would be removed

set -u

VPC_FILE="/var/lib/vpcctl/vpcs.ndjson"
DRY_RUN=0
ALL=0
NAMES=()

usage() {
  cat <<EOF
Usage: $0 [--all] [--dry-run] [vpc_name ...]

Options:
  --all       Delete all VPCs recorded in $VPC_FILE
  --dry-run   Print actions without making changes
  vpc_name    One or more VPC names to delete
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all) ALL=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) NAMES+=("$1"); shift ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root (sudo)." >&2
  exit 2
fi

if [[ ! -f "$VPC_FILE" ]]; then
  echo "No VPC metadata file found at $VPC_FILE; nothing to do." >&2
  exit 0
fi

if [[ $ALL -eq 1 ]]; then
  # collect all names from the ndjson file
  mapfile -t NAMES < <(python3 -c "
import json
import sys
path = '$VPC_FILE'
out = []
try:
    with open(path) as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                obj = json.loads(ln)
            except Exception:
                continue
            n = obj.get('name')
            if n:
                out.append(n)
    print('\n'.join(out))
except Exception as e:
    sys.stderr.write(f'Error reading VPC file: {e}\n')
    sys.exit(1)
")
fi

if [[ ${#NAMES[@]} -eq 0 ]]; then
  echo "No VPC names provided and --all not specified. Use --all or provide one or more vpc names." >&2
  usage
  exit 1
fi

echo "Will remove VPCs: ${NAMES[*]}"
if [[ $DRY_RUN -eq 0 ]]; then
  echo "Proceeding with deletion. Press Ctrl-C to abort..."
  sleep 1
fi

for vpc in "${NAMES[@]}"; do
  echo "----"
  echo "Processing VPC: $vpc"
  rec=$(python3 -c "
import json
import sys
path = '$VPC_FILE'
name = '$vpc'
try:
    with open(path) as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                obj = json.loads(ln)
            except Exception:
                continue
            if obj.get('name') == name:
                print(json.dumps(obj))
                sys.exit(0)
except Exception as e:
    sys.stderr.write(f'Error reading VPC file: {e}\n')
    sys.exit(1)
")

  if [[ -z "$rec" ]]; then
    echo "No persisted record for $vpc; skipping."
    continue
  else
    # extract fields from JSON record
    bridge_name=$(python3 -c "import json; obj=json.loads('$rec'); print(obj.get('bridge',''))")
    public_ns=$(python3 -c "import json; obj=json.loads('$rec'); print(obj.get('public_ns',''))")
    private_ns=$(python3 -c "import json; obj=json.loads('$rec'); print(obj.get('private_ns',''))")
    interface=$(python3 -c "import json; obj=json.loads('$rec'); print(obj.get('interface',''))")
    public_subnet=$(python3 -c "import json; obj=json.loads('$rec'); print(obj.get('public_subnet',''))")
    
    # Derive host veth names deterministically (same as create command)
    veth_pub_host="veth-$(echo -n "${vpc}-pub-h" | md5sum | cut -c1-10)"
    veth_pri_host="veth-$(echo -n "${vpc}-pri-h" | md5sum | cut -c1-10)"
  fi

  echo "Target bridge: ${bridge_name:-<unknown>}"
  echo "Target public ns: ${public_ns:-<unknown>} private ns: ${private_ns:-<unknown>}"
  echo "Target host veths: ${veth_pub_host}, ${veth_pri_host}"

  # Prepare commands list
  cmds=()
  # remove iptables rules if interface/public_subnet present
  if [[ -n "${interface:-}" && -n "${public_subnet:-}" ]]; then
    cmds+=("iptables -t nat -C POSTROUTING -s ${public_subnet} -o ${interface} -j MASQUERADE || true")
    cmds+=("iptables -t nat -D POSTROUTING -s ${public_subnet} -o ${interface} -j MASQUERADE || true")
    cmds+=("iptables -C FORWARD -i ${interface} -o ${bridge_name} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || true")
    cmds+=("iptables -D FORWARD -i ${interface} -o ${bridge_name} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || true")
    cmds+=("iptables -C FORWARD -i ${bridge_name} -o ${interface} -j ACCEPT || true")
    cmds+=("iptables -D FORWARD -i ${bridge_name} -o ${interface} -j ACCEPT || true")
    cmds+=("iptables -C FORWARD -p tcp -d ${public_subnet} -m multiport --dports 80,443,22 -j ACCEPT || true")
    cmds+=("iptables -D FORWARD -p tcp -d ${public_subnet} -m multiport --dports 80,443,22 -j ACCEPT || true")
  fi

  # netns delete
  if [[ -n "$public_ns" ]]; then
    cmds+=("ip netns delete ${public_ns} || true")
  fi
  if [[ -n "$private_ns" ]]; then
    cmds+=("ip netns delete ${private_ns} || true")
  fi

  # delete host veths
  cmds+=("ip link delete ${veth_pub_host} type veth || true")
  cmds+=("ip link delete ${veth_pri_host} type veth || true")

  # delete bridge
  cmds+=("ip link delete ${bridge_name} type bridge || true")

  # print or execute
  for c in "${cmds[@]}"; do
    if [[ $DRY_RUN -eq 1 ]]; then
      echo "DRY-RUN: $c"
    else
      echo "+ $c"
      eval $c
    fi
  done

  # remove ndjson entry
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "DRY-RUN: would remove $vpc from $VPC_FILE"
  else
    python3 -c "
import json
path = '$VPC_FILE'
name = '$vpc'
out = []
try:
    with open(path) as f:
        for ln in f:
            ln2 = ln.strip()
            if not ln2:
                continue
            try:
                obj = json.loads(ln2)
            except Exception:
                out.append(ln)
                continue
            if obj.get('name') != name:
                out.append(ln)
    with open(path, 'w') as f:
        f.writelines(out)
except Exception as e:
    import sys
    sys.stderr.write(f'Error updating VPC file: {e}\n')
    sys.exit(1)
"
    echo "Removed $vpc from $VPC_FILE"
  fi

done

echo "Cleanup complete."
