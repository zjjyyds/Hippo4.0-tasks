#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/workspace/binwalk"
if [ ! -d "$REPO_DIR" ]; then
    if [ -f "Cargo.toml" ]; then
        REPO_DIR="$(pwd)"
    else
        REPO_DIR="."
    fi
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH_FILE="$SCRIPT_DIR/solution.patch"

if [ ! -f "$PATCH_FILE" ]; then
    echo "[-] Solution patch not found at $PATCH_FILE"
    exit 1
fi

echo "[*] Applying solution patch to $REPO_DIR..."
cd "$REPO_DIR"

# Agent workspaces begin with optional, public starter boilerplate. Replace
# only the boilerplate with the full correct implementation for Oracle tests.
# No upstream code, tests, verifier or dependencies are bypassed.
if grep -q "STARTER ONLY" src/binwalk.rs 2>/dev/null; then
    git restore -- src/binwalk.rs src/lib.rs src/main.rs
    rm -rf src/derived
fi
git apply --check "$PATCH_FILE"
git apply "$PATCH_FILE"

echo "[*] Building modified Binwalk codebase..."
cargo build --offline

echo "[+] Oracle solution successfully applied and built."
