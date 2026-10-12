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

WORKSPACE_DIR="/workspace/binwalk"
BUILD_DIR="$(mktemp -d /tmp/dbsf-build.XXXXXX)"

if [ "$(id -u)" != "0" ]; then
    fail "Verifier must run as root to isolate the submitted harness"
fi

# Build scripts, proc macros and test bodies also execute submission code.
# They must not be able to change /tests or forge the verifier reward.
chmod 700 "$REWARD_DIR"
record_result 0
mkdir -p "$BUILD_DIR"
chown -R 10001:10001 "$BUILD_DIR" "$WORKSPACE_DIR" /usr/local/cargo
chmod -R go-w /tests

run_build() {
    setpriv --reuid=10001 --regid=10001 --clear-groups --no-new-privs \
        env HOME="$BUILD_DIR" XDG_CONFIG_HOME=/opt/dbsf-build-config CARGO_HOME=/usr/local/cargo "$@"
}

if [ ! -d "$WORKSPACE_DIR" ]; then
    fail "Workspace directory $WORKSPACE_DIR does not exist"
fi

echo "[*] Step 0: Verifying dependency and external runtime constraints..."
if ! (cd "$WORKSPACE_DIR" && sha256sum -c /tests/upstream-cargo.sha256 >/dev/null 2>&1); then
    fail "Cargo.toml or Cargo.lock was modified (adding external crate dependencies is prohibited)"
fi

# Verify no external subprocess invocation (std::process::Command) was added to derived stream analysis
CHANGED_FILES=$(run_build git -c safe.directory="$WORKSPACE_DIR" -C "$WORKSPACE_DIR" status --porcelain | awk '{print $2}')
for f in $CHANGED_FILES; do
    if [ "$f" != "src/extractors/common.rs" ] && [ -f "$WORKSPACE_DIR/$f" ]; then
        if grep -E "process::Command|Command::new" "$WORKSPACE_DIR/$f" >/dev/null 2>&1; then
            fail "External runtime subprocess invocation detected in $f (prohibited by specification)"
        fi
    fi
done
echo "[+] Dependency and runtime isolation constraints verified."

echo "[*] Step 1: Running all existing Binwalk library unit tests and built-in extractor regression tests..."
if ! (cd "$WORKSPACE_DIR" && run_build cargo test --offline --locked --lib --bins \
        --test androidsparse --test arcadyan --test bmp --test bzip2 \
        --test csman --test gzip --test jpeg --test matter_ota \
        --test mbr --test pdf --test png --test qcow \
        --test riff --test romfs); then
    fail "Upstream unit or built-in extractor regression tests failed on modified codebase"
fi
echo "[+] All upstream unit and built-in extractor regression tests passed."

echo "[*] Step 2: Compiling Rust test harness against modified Binwalk library..."
HARNESS_DIR="/tests/rust_harness"
if ! (cd "$HARNESS_DIR" && run_build env CARGO_TARGET_DIR="$BUILD_DIR/harness-target" \
        cargo build --release --offline --locked --manifest-path "$HARNESS_DIR/Cargo.toml"); then
    fail "Failed to compile rust_harness against binwalk library (API contract missing or build error)"
fi

HARNESS_BIN="$BUILD_DIR/harness-target/release/rust_harness"
if [ ! -f "$HARNESS_BIN" ]; then
    fail "Harness binary not found at $HARNESS_BIN"
fi
echo "[+] Test harness compiled successfully."

if ! (cd "$WORKSPACE_DIR" && sha256sum -c /tests/upstream-cargo.sha256 >/dev/null 2>&1); then
    fail "Cargo.toml or Cargo.lock changed during the untrusted build"
fi

echo "[*] Step 3: Executing fresh private cases with payload hashes and a trusted scanner..."
if ! python3 /tests/verify.py "$HARNESS_BIN" /tests/trusted_signature_reference /tests/runtime-root; then
    fail "One or more DBSF test cases failed"
fi

pass "All regression and derived stream test cases passed successfully."
