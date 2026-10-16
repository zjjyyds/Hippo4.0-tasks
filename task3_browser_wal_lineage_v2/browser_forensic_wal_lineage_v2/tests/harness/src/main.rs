use std::path::Path;
fn main() {
    let root = match std::env::args().nth(1) {
        Some(s) => s,
        None => { eprintln!("missing evidence directory"); std::process::exit(2); }
    };
    match browser_forensic_core::wal_lineage::inspect_wal_lineage(Path::new(&root)) {
        Ok(report) => match serde_json::to_string(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => { eprintln!("JSON: {e}"); std::process::exit(3); }
        },
        Err(e) => { eprintln!("evidence: {e}"); std::process::exit(4); }
    }
}
