#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_DIR="/workspace/d4-net-forensics"
if [ ! -d "$WORKSPACE_DIR" ]; then
    if [ -f "firmware/net_forensics.py" ]; then
        WORKSPACE_DIR="$(pwd)"
    else
        WORKSPACE_DIR="."
    fi
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH_FILE="$SCRIPT_DIR/solution.patch"

if [ ! -f "$PATCH_FILE" ]; then
    echo "[-] Solution patch not found at $PATCH_FILE"
    exit 1
fi

echo "[*] Applying TCP Evidence Reconstruction solution patch to $WORKSPACE_DIR..."
cd "$WORKSPACE_DIR"

git apply --check "$PATCH_FILE"
git apply "$PATCH_FILE"

echo "[*] Verifying upstream unit test compatibility..."
python3 -m unittest discover tests

echo "[+] Oracle solution successfully applied and verified."
