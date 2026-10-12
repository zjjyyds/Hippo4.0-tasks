#!/usr/bin/env bash
# Oracle solution: apply the reference implementation, run upstream regression,
# then run the opt-in analysis on one bundled-style smoke collection to prove
# the CLI contract works end to end.
set -euo pipefail

REPO_DIR="/workspace/hindsight"
if [ ! -d "$REPO_DIR" ]; then
    if [ -f "Cargo.toml" ] || [ -f "pyproject.toml" ]; then
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
git apply "$PATCH_FILE"

echo "[*] Running upstream Hindsight regression tests..."
python -m pytest tests/ -q

echo "[*] Building a minimal smoke collection and running the opt-in analysis..."
SMOKE="$(mktemp -d)"
mkdir -p "$SMOKE/case/snapshots/s0/Default/Extensions/abcdefghijklmnopabcdefghijklmnop/1.0.0_0"
python3 - "$SMOKE" << 'PYEOF'
import json, os, sqlite3, sys
root = sys.argv[1]
prof = os.path.join(root, "case", "snapshots", "s0", "Default")
sqlite3.connect(os.path.join(prof, "History")).close()
ext = os.path.join(prof, "Extensions", "abcdefghijklmnopabcdefghijklmnop", "1.0.0_0")
body = b"// smoke worker\n"
with open(os.path.join(ext, "manifest.json"), "w") as f:
    json.dump({"manifest_version": 3, "name": "Smoke", "version": "1.0.0",
               "background": {"service_worker": "background.js"}}, f)
with open(os.path.join(ext, "background.js"), "wb") as f:
    f.write(body)
with open(os.path.join(prof, "Secure Preferences"), "w") as f:
    json.dump({"extensions": {"settings": {
        "abcdefghijklmnopabcdefghijklmnop": {"location": 1, "state": 1,
                                             "first_install_time": "13400000000000000"}}}}, f)
with open(os.path.join(root, "case", "collection.json"), "w") as f:
    json.dump({"schema_version": 1, "profile_key": "smoke/host/profile",
               "snapshots": [{"id": "s0", "captured_at": "2026-08-01T10:00:00Z",
                              "path": "snapshots/s0/Default",
                              "complete_artifacts": ["extension_inventory", "extension_disk"]}]}, f)
PYEOF

python3 hindsight.py -i "$SMOKE/case" --extension-worker-report "$SMOKE/report.json"

python3 - "$SMOKE/report.json" << 'PYEOF'
import json, sys
report = json.load(open(sys.argv[1]))
assert report["schema_version"] == 1
profile = report["profiles"][0]
assert profile["profile_key"] == "smoke/host/profile"
entry = profile["extensions"][0]
assert entry["extension_id"] == "abcdefghijklmnopabcdefghijklmnop"
assert entry["current_state"] == "ACTIVE", entry["current_state"]
print("[+] Smoke report semantics OK (ACTIVE)")
PYEOF

echo "[+] Oracle solution applied and verified."
