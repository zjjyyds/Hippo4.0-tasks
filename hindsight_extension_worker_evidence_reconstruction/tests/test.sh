#!/usr/bin/env bash
set -uo pipefail

REWARD_DIR="/logs/verifier"
mkdir -p "$REWARD_DIR"

record_result() { echo "$1" > "$REWARD_DIR/reward.txt"; }
fail() { echo "[-] FAIL: $1"; record_result 0; exit 1; }
pass() { echo "[+] PASS: $1"; record_result 1; exit 0; }

WORKSPACE_DIR="/workspace/hindsight"
if [ ! -d "$WORKSPACE_DIR" ]; then
    fail "Workspace directory $WORKSPACE_DIR does not exist"
fi

echo "[*] Step 1: Running upstream Hindsight regression tests..."
if ! (cd "$WORKSPACE_DIR" && python -m pytest tests/ -q); then
    fail "Upstream Hindsight tests failed on modified codebase"
fi
echo "[+] Upstream regression tests passed."

echo "[*] Step 2: Running the opt-in analysis on every forensic case..."
REPORTS_DIR="/tmp/ewr_reports"
rm -rf "$REPORTS_DIR"
mkdir -p "$REPORTS_DIR"
shopt -s nullglob
CASES=(/tests/fixtures/cases/*)
if [ ${#CASES[@]} -eq 0 ]; then
    fail "No forensic cases found"
fi
for case_dir in "${CASES[@]}"; do
    case_id="$(basename "$case_dir")"
    if ! timeout 60 python3 "$WORKSPACE_DIR/hindsight.py" \
            -i "$case_dir" \
            --extension-worker-report "$REPORTS_DIR/$case_id.json" \
            > "/tmp/${case_id}.log" 2>&1; then
        fail "analysis crashed or timed out on $case_id (see /tmp/${case_id}.log)"
    fi
done
echo "[+] All ${#CASES[@]} cases analyzed without crashing."

echo "[*] Step 3: Verifying reports against expected forensic semantics..."
if ! python3 /tests/verify.py /tests/fixtures/cases /tests/expected "$REPORTS_DIR"; then
    fail "One or more evidence-semantics checks failed"
fi

pass "Extension worker evidence reconstruction verified."
