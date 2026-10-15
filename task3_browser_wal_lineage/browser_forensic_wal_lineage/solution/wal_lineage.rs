//! Reconstruct the committed physical SQLite database images represented by a
//! WAL sidecar without opening or writing the evidence.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize)]
pub struct WalCommit {
    /// One-based index of the frame that commits this database image.
    pub end_frame: u32,
    /// Number of pages in the committed database image.
    pub database_pages: u32,
    /// SHA-256 of the complete, page-ordered committed image.
    pub sha256: String,
}

fn be32(data: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = data.get(..4)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

fn checksum(bytes: &[u8], little_endian: bool, mut s0: u32, mut s1: u32) -> Option<(u32,u32)> {
    if bytes.len() % 8 != 0 { return None; }
    for chunk in bytes.chunks_exact(8) {
        let x = if little_endian {
            u32::from_le_bytes(chunk[0..4].try_into().ok()?)
        } else {
            u32::from_be_bytes(chunk[0..4].try_into().ok()?)
        };
        let y = if little_endian {
            u32::from_le_bytes(chunk[4..8].try_into().ok()?)
        } else {
            u32::from_be_bytes(chunk[4..8].try_into().ok()?)
        };
        s0 = s0.wrapping_add(x).wrapping_add(s1);
        s1 = s1.wrapping_add(y).wrapping_add(s0);
    }
    Some((s0,s1))
}

fn invalid(msg: &'static str) -> io::Error { io::Error::new(ErrorKind::InvalidData, msg) }

fn hash_snapshot(
    base: &[u8], page_size: usize, pages: u32, overlay: &BTreeMap<u32, Vec<u8>>
) -> io::Result<String> {
    let mut hash = Sha256::new();
    let zeros = vec![0u8; page_size];
    for p in 1..=pages {
        if let Some(data) = overlay.get(&p) { hash.update(data); }
        else if let Some(offset) = (p as usize - 1).checked_mul(page_size) {
            if let Some(data) = base.get(offset..offset.saturating_add(page_size)) {
                hash.update(data);
            } else { hash.update(&zeros); }
        } else { return Err(invalid("page address overflow")); }
    }
    Ok(format!("{:x}", hash.finalize()))
}

/// Return the validated committed snapshots from a SQLite main file and its
/// optional `-wal` sidecar. A damaged or stale tail cannot extend the lineage.
/// The original evidence is read only; no SQLite connection is opened.
pub fn inspect_wal_lineage(db_path: &Path) -> io::Result<Vec<WalCommit>> {
    let base = fs::read(db_path)?;
    if base.len() < 100 || base.get(..16) != Some(b"SQLite format 3\0".as_slice()) {
        return Err(invalid("not a SQLite main file"));
    }
    let raw_page_size = u16::from_be_bytes([base[16],base[17]]) as usize;
    let page_size = if raw_page_size == 1 { 65536 } else { raw_page_size };
    if !(512..=65536).contains(&page_size)
        || !page_size.is_power_of_two()
        || base.len() % page_size != 0 {
        return Err(invalid("invalid main database page layout"));
    }

    let mut sidecar = db_path.as_os_str().to_os_string();
    sidecar.push("-wal");
    let wal = match fs::read(&sidecar) {
        Ok(v) => v,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    if wal.len() < 32 { return Ok(Vec::new()); }
    let Some(magic) = be32(&wal[0..4]) else { return Ok(Vec::new()); };
    let little = match magic {
        0x377f0682 => true,
        0x377f0683 => false,
        _ => return Ok(Vec::new()),
    };
    if be32(&wal[4..8]) != Some(3007000)
        || be32(&wal[8..12]) != Some(page_size as u32) {
        return Ok(Vec::new());
    }
    let Some(mut sum) = checksum(&wal[0..24], little, 0, 0) else { return Ok(Vec::new()); };
    if be32(&wal[24..28]) != Some(sum.0) || be32(&wal[28..32]) != Some(sum.1) {
        return Ok(Vec::new());
    }
    let salt1 = &wal[16..20];
    let salt2 = &wal[20..24];
    let stride = match page_size.checked_add(24) {
        Some(n) => n,
        None => return Ok(Vec::new()),
    };
    let mut overlay: BTreeMap<u32,Vec<u8>> = BTreeMap::new();
    let mut staged: Vec<(u32,Vec<u8>)> = Vec::new();
    let mut commits = Vec::new();
    let mut offset = 32usize;
    let mut frame_index = 0u32;
    while let Some(frame_end) = offset.checked_add(stride) {
        if frame_end > wal.len() { break; }
        let f = &wal[offset..frame_end];
        let Some(page_no) = be32(&f[0..4]) else { break; };
        let Some(db_pages) = be32(&f[4..8]) else { break; };
        if page_no == 0 || &f[8..12] != salt1 || &f[12..16] != salt2 { break; }
        let Some(t) = checksum(&f[0..8], little, sum.0, sum.1) else { break; };
        let Some(next) = checksum(&f[24..], little, t.0, t.1) else { break; };
        if be32(&f[16..20]) != Some(next.0) || be32(&f[20..24]) != Some(next.1) {
            break;
        }
        sum = next;
        frame_index += 1;
        staged.push((page_no, f[24..].to_vec()));
        if db_pages != 0 {
            for (p,data) in staged.drain(..) { overlay.insert(p, data); }
            overlay.retain(|p,_| *p <= db_pages);
            // A malformed commit marker cannot force unbounded image hashing.
            // A valid SQLite database never needs more pages than the base plus
            // the frames observed in this WAL prefix.
            let base_pages = base.len() / page_size;
            let theoretical_max = base_pages.saturating_add(frame_index as usize);
            if (db_pages as usize) > theoretical_max { break; }
            commits.push(WalCommit {
                end_frame: frame_index,
                database_pages: db_pages,
                sha256: hash_snapshot(&base, page_size, db_pages, &overlay)?,
            });
        }
        offset = frame_end;
    }
    Ok(commits)
}
