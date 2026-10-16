#!/usr/bin/env python3
"""Introduce the V2 public API without implementing it."""
from pathlib import Path
root = Path('/workspace/browser-forensic/crates/browser-forensic-core/src')
lib = root / 'lib.rs'
s = lib.read_text()
if 'pub mod wal_lineage;' not in s:
    s = s.replace('pub mod sqlite;\n','pub mod sqlite;\npub mod wal_lineage;\n',1)
    lib.write_text(s)
p = root / 'wal_lineage.rs'
if not p.exists():
    p.write_text('''use std::io;
use std::path::Path;
use serde::Serialize;

#[derive(Debug,Clone,Serialize)]
pub struct WalCommit { pub end_frame:u32, pub database_pages:u32, pub sha256:String }
#[derive(Debug,Clone,Serialize)]
pub struct WalCapture { pub id:String, pub base_sha256:String, pub commits:Vec<WalCommit>, pub terminal_sha256:String }
#[derive(Debug,Clone,Serialize)]
pub struct WalLink { #[serde(rename="from")] pub from:String, pub to:String, pub relation:String, pub anchors:Vec<u32> }
#[derive(Debug,Clone,Serialize)]
pub struct WalLineageReport { pub captures:Vec<WalCapture>, pub links:Vec<WalLink> }

pub fn inspect_wal_lineage(_root:&Path)->io::Result<WalLineageReport> {
    Ok(WalLineageReport {captures:Vec::new(),links:Vec::new()})
}
''')
