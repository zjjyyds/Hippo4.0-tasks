#!/usr/bin/env python3
"""Install public API and basic 24-bit BMP sampler in pristine pinned Binwalk.

Does not implement the unknown DBSF protocol (frame/CRC/TLV/XOR/reassembly).
Never removes any pre-existing upstream source.
"""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("Usage: starter.py <upstream-binwalk-checkout>")
src = Path(sys.argv[1]).resolve() / "src"

def replace(path, before, after):
    text = path.read_text()
    if text.count(before) != 1:
        raise RuntimeError(f"Unexpected upstream version in {path}: {before[:40]}")
    path.write_text(text.replace(before, after, 1))

p = src / "binwalk.rs"
replace(p,
    '    pub extractions: HashMap<String, extractors::common::ExtractionResult>,\n}',
    '    pub extractions: HashMap<String, extractors::common::ExtractionResult>,\n'
    '    #[serde(default, skip_serializing_if = "Vec::is_empty")]\n'
    '    pub derived: Vec<crate::derived::DerivedResult>,\n}')
replace(p,
    '    pub extractor_lookup_table: HashMap<String, Option<extractors::common::Extractor>>,\n}',
    '    pub extractor_lookup_table: HashMap<String, Option<extractors::common::Extractor>>,\n'
    '    pub derived_streams: bool,\n}')
replace(p,
    '    pub fn new() -> Binwalk {\n        Binwalk::configure(None, None, None, None, None, false).unwrap()\n    }\n',
    '    pub fn new() -> Binwalk {\n        Binwalk::configure(None, None, None, None, None, false).unwrap()\n'
    '    }\n\n'
    '    pub fn enable_derived_streams(&mut self, enable: bool) -> &mut Self {\n'
    '        self.derived_streams = enable;\n'
    '        self\n'
    '    }\n')
replace(p,
    '        results.file_map = self.scan(file_data);\n\n        // Only extract if told to',
    '        results.file_map = self.scan(file_data);\n'
    '        if self.derived_streams {\n'
    '            results.derived = self.scan_derived(file_data);\n'
    '        }\n\n'
    '        // Only extract if told to')
replace(p,
    '        results\n    }\n\n    /// Analyze a file on disk and optionally extract its contents.',
    '        results\n    }\n\n'
    '    /// STARTER ONLY: implement DBSF recovery and child signature analysis.\n'
    '    pub fn scan_derived(&self, _file_data: &[u8]) -> Vec<crate::derived::DerivedResult> {\n'
    '        Vec::new()\n'
    '    }\n\n'
    '    /// Analyze a file on disk and optionally extract its contents.')
replace(src / "lib.rs",
    'pub mod structures;\npub use binwalk::{AnalysisResults, Binwalk, BinwalkError};',
    'pub mod structures;\npub mod derived;\npub use binwalk::{AnalysisResults, Binwalk, BinwalkError};\npub use derived::DerivedResult;')
replace(src / "main.rs",
    'mod structures;\n\nfn main() -> ExitCode {',
    'mod structures;\nmod derived;\n\nfn main() -> ExitCode {')

newdir = src / "derived"
if newdir.exists():
    raise RuntimeError("Refusing to overwrite derived source")
newdir.mkdir()
(newdir / "mod.rs").write_text("""//! Public derived-stream result contract. Decoder deliberately omitted.
use crate::signatures::common::SignatureResult;
use serde::{Deserialize, Serialize};

pub mod bmp;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedResult {
    pub kind: String,
    pub stream_id: u32,
    pub carrier_offsets: Vec<usize>,
    pub total_payload_size: usize,
    pub payload: Vec<u8>,
    pub file_map: Vec<SignatureResult>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nested_derived: Vec<DerivedResult>,
}
""")
(newdir / "bmp.rs").write_text("""//! Routine BMP plumbing supplied with the task.
//! Frame synchronization, TLV, XOR, CRC and fragment reassembly are NOT supplied.

#[derive(Debug, Clone)]
pub struct BmpCarrier {
    pub offset: usize,
    pub size: usize,
    pub width: usize,
    pub height: usize,
    pub pixel_offset: usize,
    pub row_stride: usize,
}
fn u16le(buf: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(buf.get(at..at.checked_add(2)?)?.try_into().ok()?))
}
fn u32le(buf: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(buf.get(at..at.checked_add(4)?)?.try_into().ok()?))
}
fn i32le(buf: &[u8], at: usize) -> Option<i32> {
    Some(i32::from_le_bytes(buf.get(at..at.checked_add(4)?)?.try_into().ok()?))
}
/// Find complete, nonoverlapping 24-bit BI_RGB bottom-up carriers.
pub fn find_24bit_carriers(data: &[u8]) -> Vec<BmpCarrier> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i.checked_add(54).is_some_and(|end| end <= data.len()) {
        if &data[i..i + 2] != b"BM" {
            i += 1;
            continue;
        }
        let parsed = (|| -> Option<BmpCarrier> {
            let size = u32le(data, i + 2)? as usize;
            let pixel_offset = u32le(data, i + 10)? as usize;
            let dib_size = u32le(data, i + 14)?;
            let width = i32le(data, i + 18)?;
            let height = i32le(data, i + 22)?;
            if dib_size != 40 || width <= 0 || height <= 0
                || u16le(data, i + 26)? != 1 || u16le(data, i + 28)? != 24
                || u32le(data, i + 30)? != 0 || pixel_offset < 54 {
                return None;
            }
            let width = usize::try_from(width).ok()?;
            let height = usize::try_from(height).ok()?;
            let row_stride = width.checked_mul(3)?.checked_add(3)? / 4 * 4;
            let end = pixel_offset.checked_add(row_stride.checked_mul(height)?)?;
            if end > size || i.checked_add(size)? > data.len() {
                return None;
            }
            Some(BmpCarrier { offset: i, size, width, height, pixel_offset, row_stride })
        })();
        if let Some(carrier) = parsed {
            i += carrier.size;
            out.push(carrier);
        } else {
            i += 1;
        }
    }
    out
}
/// Raw B,G,R pixel LSBs in logical top-to-bottom row order.
/// Do not reset a stream's bit phase at carrier boundaries.
pub fn carrier_bits(data: &[u8], carrier: &BmpCarrier) -> Vec<u8> {
    let mut bits = Vec::with_capacity(carrier.width.saturating_mul(carrier.height).saturating_mul(3));
    let start = carrier.offset + carrier.pixel_offset;
    for row_idx in (0..carrier.height).rev() {
        let row = start + row_idx * carrier.row_stride;
        for x in 0..carrier.width {
            let pixel = row + x * 3;
            for channel in 0..3 {
                bits.push(data[pixel + channel] & 1);
            }
        }
    }
    bits
}
""")
print("Public API and BMP sampler installed (protocol decoder remains to implement).")
