#!/usr/bin/env bash
set -euo pipefail

DRY_RUN=0

usage() {
	cat <<EOF
Usage: $0 [--dry-run]

Simple pre-run installer for required packages (focused on Debian/Ubuntu).
Options:
  --dry-run    Print the actions that would be taken but don't run them.
EOF
	exit 1
}

while [[ ${#} -gt 0 ]]; do
	case "$1" in
		--dry-run|-n) DRY_RUN=1; shift ;;
		--help|-h) usage ;;
		*) echo "Unknown argument: $1"; usage ;;
	esac
done

echo "Preparing to install relevant dependencies..."

# Packages required by this project
PACKAGES=(iproute2 bridge-utils iptables python3-venv)

# Detect package manager (prefer apt-get)
if command -v apt-get >/dev/null 2>&1; then
	PM=apt
else
	echo "Only apt-based systems are supported by this script."
	echo "Please install the following packages manually: ${PACKAGES[*]}"
	exit 1
fi

install_cmd() {
	if [[ "$PM" == "apt" ]]; then
		sudo apt-get update -y
		sudo apt-get install -y "${PACKAGES[@]}"
	fi
}

if [[ $DRY_RUN -eq 1 ]]; then
	echo "DRY-RUN mode: The script would run the following commands:"
	if [[ "$PM" == "apt" ]]; then
		echo "sudo apt-get update -y"
		echo "sudo apt-get install -y ${PACKAGES[*]}"
	fi
	exit 0
fi

echo "Checking for already-installed packages..."
to_install=()
for pkg in "${PACKAGES[@]}"; do
	if dpkg -s "$pkg" >/dev/null 2>&1; then
		echo "  - $pkg is already installed"
	else
		echo "  - $pkg will be installed"
		to_install+=("$pkg")
	fi
done

if [[ ${#to_install[@]} -eq 0 ]]; then
	echo "All required packages are already installed."
	exit 0
fi

echo "Installing packages: ${to_install[*]}"
if [[ "$PM" == "apt" ]]; then
	sudo apt-get update -y
	sudo apt-get install -y "${to_install[@]}"
fi

echo "Pre-run installation complete."