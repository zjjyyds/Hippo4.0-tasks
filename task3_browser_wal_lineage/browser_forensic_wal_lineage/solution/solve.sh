#!/usr/bin/env bash
set -euo pipefail
cp "$(dirname "$0")/wal_lineage.rs" /workspace/browser-forensic/crates/browser-forensic-core/src/wal_lineage.rs
cd /workspace/browser-forensic
cargo build --offline --locked -p browser-forensic-core
