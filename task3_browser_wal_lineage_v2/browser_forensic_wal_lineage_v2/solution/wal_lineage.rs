//! Read-only, evidence-limited cross-acquisition SQLite WAL lineage.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WalCommit {
    pub end_frame: u32,
    pub database_pages: u32,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WalCapture {
    pub id: String,
    pub base_sha256: String,
    pub commits: Vec<WalCommit>,
    pub terminal_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WalLink {
    #[serde(rename = "from")]
    pub from: String,
    pub to: String,
    pub relation: String,
    pub anchors: Vec<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WalLineageReport {
    pub captures: Vec<WalCapture>,
    pub links: Vec<WalLink>,
}

#[derive(Debug, Deserialize)]
struct Manifest { captures: Vec<Entry> }

#[derive(Debug, Deserialize)]
struct Entry { id: String, order: i64, db: String }

struct Evidence {
    main: Vec<u8>,
    wal: Option<Vec<u8>>,
    page_size: usize,
    view: WalCapture,
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, msg)
}

fn be32(b: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(..4)?.try_into().ok()?))
}

fn wal_checksum(bytes: &[u8], little: bool, mut a: u32, mut b: u32) -> Option<(u32,u32)> {
    if bytes.len() % 8 != 0 { return None; }
    for chunk in bytes.chunks_exact(8) {
        let first: [u8;4] = chunk.get(0..4)?.try_into().ok()?;
        let second: [u8;4] = chunk.get(4..8)?.try_into().ok()?;
        let x = if little { u32::from_le_bytes(first) } else { u32::from_be_bytes(first) };
        let y = if little { u32::from_le_bytes(second) } else { u32::from_be_bytes(second) };
        a = a.wrapping_add(x).wrapping_add(b);
        b = b.wrapping_add(y).wrapping_add(a);
    }
    Some((a,b))
}

fn digest(data: &[u8]) -> String { format!("{:x}", Sha256::digest(data)) }

fn snapshot_hash(main: &[u8], page_size: usize, pages: u32, versions: &BTreeMap<u32,Vec<u8>>) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let zero = vec![0u8; page_size];
    for p in 1..=pages {
        if let Some(bytes) = versions.get(&p) {
            hasher.update(bytes);
        } else {
            let at = (p as usize).checked_sub(1).and_then(|n|n.checked_mul(page_size))
                .ok_or_else(||invalid("page position overflow"))?;
            if let Some(bytes) = main.get(at..at.saturating_add(page_size)) {
                hasher.update(bytes);
            } else {
                hasher.update(&zero);
            }
        }
    }
    Ok(format!("{:x}",hasher.finalize()))
}

fn parse_image(main: &[u8], wal: Option<&[u8]>) -> io::Result<(usize, Vec<WalCommit>)> {
    if main.len() < 100 || main.get(..16) != Some(b"SQLite format 3\0".as_slice()) {
        return Err(invalid("not a SQLite main database"));
    }
    let raw = u16::from_be_bytes([main[16],main[17]]) as usize;
    let size = if raw == 1 { 65536 } else { raw };
    if !(512..=65536).contains(&size) || !size.is_power_of_two() || main.len() % size != 0 {
        return Err(invalid("invalid SQLite page layout"));
    }
    let Some(wal) = wal else { return Ok((size,Vec::new())); };
    if wal.len() < 32 { return Ok((size,Vec::new())); }
    let Some(magic) = be32(&wal[..4]) else { return Ok((size,Vec::new())); };
    let little = match magic {
        0x377f0682 => true,
        0x377f0683 => false,
        _ => return Ok((size,Vec::new())),
    };
    if be32(&wal[4..8]) != Some(3007000) || be32(&wal[8..12]) != Some(size as u32) {
        return Ok((size,Vec::new()));
    }
    let Some(mut sum) = wal_checksum(&wal[..24],little,0,0) else {return Ok((size,Vec::new()));};
    if be32(&wal[24..28]) != Some(sum.0) || be32(&wal[28..32]) != Some(sum.1) {
        return Ok((size,Vec::new()));
    }
    let salts = &wal[16..24];
    let stride = size.checked_add(24).ok_or_else(||invalid("frame size"))?;
    let mut overlay:BTreeMap<u32,Vec<u8>> = BTreeMap::new();
    let mut pending:BTreeMap<u32,Vec<u8>> = BTreeMap::new();
    let mut commits = Vec::new();
    let mut at=32usize;
    let mut frames=0u32;
    while let Some(end) = at.checked_add(stride) {
        if end > wal.len() { break; }
        let frame = &wal[at..end];
        let Some(page) = be32(&frame[0..4]) else {break;};
        let Some(committed_pages) = be32(&frame[4..8]) else {break;};
        if page==0 || &frame[8..16]!=salts {break;}
        let Some(prefix) = wal_checksum(&frame[..8],little,sum.0,sum.1) else {break;};
        let Some(next) = wal_checksum(&frame[24..],little,prefix.0,prefix.1) else {break;};
        if be32(&frame[16..20])!=Some(next.0) || be32(&frame[20..24])!=Some(next.1) {break;}
        frames+=1;
        sum=next;
        pending.insert(page,frame[24..].to_vec());
        if committed_pages!=0 {
            if committed_pages as usize > main.len()/size + frames as usize { break; }
            overlay.append(&mut pending);
            overlay.retain(|k,_| *k<=committed_pages);
            commits.push(WalCommit {
                end_frame:frames,
                database_pages:committed_pages,
                sha256:snapshot_hash(main,size,committed_pages,&overlay)?,
            });
        }
        at=end;
    }
    Ok((size,commits))
}

fn load(root: &Path, entry: &Entry) -> io::Result<Evidence> {
    let relative = Path::new(&entry.db);
    if relative.as_os_str().is_empty() || !relative.components().all(|c|matches!(c, Component::Normal(_))) {
        return Err(invalid("invalid evidence path"));
    }
    let path=root.join(relative);
    let main=fs::read(&path)?;
    let mut wal_name=path.into_os_string();
    wal_name.push("-wal");
    let wal=match fs::read(&wal_name) {
        Ok(v)=>Some(v),
        Err(e) if e.kind()==ErrorKind::NotFound=>None,
        Err(e)=>return Err(e),
    };
    let (page_size,commits)=parse_image(&main,wal.as_deref())?;
    let base_sha256=digest(&main);
    let terminal_sha256=commits.last().map_or_else(||base_sha256.clone(),|c|c.sha256.clone());
    Ok(Evidence {
        main,wal,page_size,
        view:WalCapture {id:entry.id.clone(),base_sha256,commits,terminal_sha256}
    })
}

fn shared_wal_prefix(a:&Evidence,b:&Evidence)->bool {
    if a.view.base_sha256 != b.view.base_sha256 || a.view.commits.is_empty() {return false;}
    let (Some(wa),Some(wb))=(&a.wal,&b.wal) else {return false;};
    let last=&a.view.commits[a.view.commits.len()-1];
    let Some(limit)=(last.end_frame as usize).checked_mul(a.page_size+24).and_then(|n|n.checked_add(32)) else {return false;};
    if wa.len()<limit || wb.len()<limit || wa[..limit]!=wb[..limit] {return false;}
    b.view.commits.starts_with(&a.view.commits)
}

fn classify(a:&Evidence,b:&Evidence)->(&'static str,Vec<u32>) {
    if a.main==b.main && a.wal==b.wal {return ("identical_evidence",Vec::new());}
    if shared_wal_prefix(a,b) {return ("shared_wal_prefix",Vec::new());}
    let anchors:Vec<u32> = a.view.commits.iter()
        .filter(|c|c.sha256==b.view.base_sha256)
        .map(|c|c.end_frame)
        .collect();
    if !anchors.is_empty() && a.view.base_sha256!=b.view.base_sha256 {
        return ("checkpoint_compatible",anchors);
    }
    if a.view.terminal_sha256==b.view.terminal_sha256 {
        return ("equal_result_only",Vec::new());
    }
    ("unproven",Vec::new())
}

/// Report only evidence-supported physical state relationships across acquisitions.
/// The report never asserts that byte equality alone proves event identity.
pub fn inspect_wal_lineage(root:&Path)->io::Result<WalLineageReport> {
    let data=fs::read(root.join("manifest.json"))?;
    let mut manifest:Manifest=serde_json::from_slice(&data).map_err(|_|invalid("invalid capture manifest"))?;
    manifest.captures.sort_by(|a,b|a.order.cmp(&b.order));
    let mut seen_id=BTreeSet::new();
    let mut seen_order=BTreeSet::new();
    for entry in &manifest.captures {
        if !seen_id.insert(entry.id.as_str()) || !seen_order.insert(entry.order) || entry.id.is_empty() {
            return Err(invalid("duplicate or empty capture identity"));
        }
    }
    let mut evidence=Vec::with_capacity(manifest.captures.len());
    for entry in &manifest.captures {evidence.push(load(root,entry)?);}
    let mut links=Vec::new();
    for (i,a) in evidence.iter().enumerate() {
        for b in evidence.iter().skip(i+1) {
            let (kind,anchors)=classify(a,b);
            links.push(WalLink {
                from:a.view.id.clone(),to:b.view.id.clone(),relation:kind.to_string(),anchors,
            });
        }
    }
    Ok(WalLineageReport {captures:evidence.into_iter().map(|e|e.view).collect(),links})
}
