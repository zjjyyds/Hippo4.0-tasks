use std::path::Path;

fn main() {
    let path = match std::env::args().nth(1) {
        Some(s) => s,
        None => { eprintln!("missing database path"); std::process::exit(2); }
    };
    match browser_forensic_core::wal_lineage::inspect_wal_lineage(Path::new(&path)) {
        Ok(commits) => match serde_json::to_string(&commits) {
            Ok(out) => println!("{out}"),
            Err(e) => { eprintln!("JSON: {e}"); std::process::exit(3); }
        },
        Err(e) => { eprintln!("evidence: {e}"); std::process::exit(4); }
    }
}
