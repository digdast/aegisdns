#!/usr/bin/env bash
# AegisDNS - Linux / macOS Launcher

set -e

echo "========================================================"
echo "  🛡️  AegisDNS - Recursive DoH Resolver & Threat Engine"
echo "  Port 53 (UDP/TCP) | Web UI & DoH: http://localhost:5380"
echo "========================================================"

# Check for root/sudo since binding port 53 requires privileges on Linux
if [ "$EUID" -ne 0 ]; then
  echo "⚠️ Warning: Binding to port 53 on Linux typically requires root privileges."
  echo "If it fails with Permission Denied, run: sudo ./run.sh"
  echo "Or grant capabilities: sudo setcap 'cap_net_bind_service=+ep' \$(which python3)"
  echo ""
fi

# Ensure Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 could not be found. Please install Python 3.10+."
    exit 1
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

echo "[*] Ensuring dependencies..."
pip3 install -r requirements.txt --quiet

echo "[*] Launching AegisDNS..."
export PYTHONPATH="$SCRIPT_DIR"
python3 -m aegisdns.main
