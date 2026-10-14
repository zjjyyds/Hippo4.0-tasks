#!/usr/bin/env bash
set -euo pipefail

REWARD_DIR="/logs/verifier"
mkdir -p "$REWARD_DIR"

record_result() {
    local reward="$1"
    echo "$reward" > "$REWARD_DIR/reward.txt"
}

fail() {
    local msg="$1"
    echo "[-] FAIL: $msg"
    record_result 0
    exit 1
}

pass() {
    local msg="$1"
    echo "[+] PASS: $msg"
    record_result 1
    exit 0
}

WORKSPACE_DIR="/workspace/d4-net-forensics"

if [ ! -d "$WORKSPACE_DIR" ]; then
    fail "Workspace directory $WORKSPACE_DIR does not exist"
fi

# Ensure test scripts are read-only
chmod -R go-w /tests 2>/dev/null || true
chmod 700 "$REWARD_DIR"
record_result 0

echo "[*] Step 1: Running D4 TCP Evidence Reconstruction Verifier (48 checks)..."
if ! python3 /tests/verify.py "$WORKSPACE_DIR"; then
    fail "D4 TCP Evidence Reconstruction verification failed"
fi

pass "All 48 TCP evidence condition checks and upstream regression tests passed successfully."
