#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -eq 0 ]]; then SUDO=""; else SUDO="sudo"; fi
$SUDO apt-get update
$SUDO apt-get install -y python3 python3-venv python3-pip nmap git golang-go
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -e '.[dev,pdf]'
echo "Install optional ProjectDiscovery tools from their signed official releases, then run scripts/check_dependencies.sh."
echo "Review config/nmap_scripts.yaml and config/nuclei_policy.yaml before production use."

