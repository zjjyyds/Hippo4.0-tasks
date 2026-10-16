#!/usr/bin/env bash
set -euo pipefail
mkdir -p /logs/verifier
chmod 700 /logs/verifier
printf '0\n' > /logs/verifier/reward.txt
fail() { echo "[FAIL] $*"; exit 1; }
[ "$(id -u)" = 0 ] || fail 'requires privileged verifier controller'
[ -d /workspace/browser-forensic/crates/browser-forensic-core ] || fail 'candidate artifact missing'
chmod -R go-rwx /tests
# Compile untrusted candidate code with UID 10001; it cannot read private
# verifier source, test data, or the reward file.
mkdir -p /tmp/wal-build
cp -r /tests/harness /tmp/wal-build/harness
chown -R 10001:10001 /tmp/wal-build
chown -R 10001:10001 /workspace/browser-forensic
chmod -R go+rX /workspace/browser-forensic /usr/local/cargo
export CARGO_TARGET_DIR=/opt/wal-target
chmod -R a+rX /opt/wal-target
chown -R 10001:10001 /opt/wal-target /usr/local/cargo
cd /tmp/wal-build/harness
if ! setpriv --reuid=10001 --regid=10001 --clear-groups --no-new-privs \
  env HOME=/tmp/wal-build CARGO_HOME=/usr/local/cargo CARGO_TARGET_DIR=/opt/wal-target \
  cargo build --offline --quiet; then
  fail 'submitted Rust API did not build'
fi
if ! setpriv --reuid=10001 --regid=10001 --clear-groups --no-new-privs \
  env HOME=/tmp/wal-build CARGO_HOME=/usr/local/cargo CARGO_TARGET_DIR=/opt/wal-target \
  cargo test --offline --locked --quiet -p browser-forensic-core \
  --manifest-path /workspace/browser-forensic/Cargo.toml --lib; then
  fail 'upstream core unit regressions'
fi
# Run the model-linked binary without access to tests and the result directory.
if python3 -B /tests/verify.py /opt/wal-target/debug/wal_lineage_harness; then
    printf '1\n' > /logs/verifier/reward.txt
    echo '[PASS] committed physical evidence verified'
else
    fail 'wrong or missing committed evidence'
fi
