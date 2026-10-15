#!/usr/bin/env python3
"""Add the public API and an intentionally empty implementation to the checkout."""
from pathlib import Path

root = Path('/workspace/browser-forensic/crates/browser-forensic-core/src')
lib = root / 'lib.rs'
body = lib.read_text()
if 'pub mod wal_lineage;' not in body:
    body = body.replace('pub mod sqlite;\n', 'pub mod sqlite;\npub mod wal_lineage;\n', 1)
    lib.write_text(body)

module = root / 'wal_lineage.rs'
if not module.exists():
    module.write_text('''use std::io;
use std::path::Path;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct WalCommit {
    pub end_frame: u32,
    pub database_pages: u32,
    pub sha256: String,
}

/// Recover chronological, committed SQLite WAL database images.
pub fn inspect_wal_lineage(_db_path: &Path) -> io::Result<Vec<WalCommit>> {
    Ok(Vec::new())
}
''')
