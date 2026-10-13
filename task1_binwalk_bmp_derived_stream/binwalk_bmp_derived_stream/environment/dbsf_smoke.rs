//! Public manual driver: sample input -> real library output.
use binwalk::Binwalk;
use std::{env, fs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = env::args().nth(1).ok_or("usage: dbsf_smoke <path> [--legacy]")?;
    let legacy = env::args().nth(2).as_deref() == Some("--legacy");
    let data = fs::read(file)?;
    let mut scanner = Binwalk::new();
    scanner.enable_derived_streams(!legacy);
    let result = scanner.analyze_buf(&data, "public-specimen", false);
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
