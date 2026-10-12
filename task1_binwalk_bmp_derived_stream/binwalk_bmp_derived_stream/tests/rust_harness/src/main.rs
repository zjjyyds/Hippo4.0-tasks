use binwalk::Binwalk;
use clap::Parser;
use std::io::{self, Read};

#[derive(Parser, Debug)]
#[command(author, version, about = "Binwalk Library Test Harness")]
struct Args {
    /// Opt-in to derived stream scanning
    #[arg(long)]
    derived: bool,

    /// Signature include filters (comma-separated)
    #[arg(short = 'y', long, value_delimiter = ',')]
    include: Option<Vec<String>>,

    /// Signature exclude filters (comma-separated)
    #[arg(short = 'x', long, value_delimiter = ',')]
    exclude: Option<Vec<String>>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut file_data = Vec::new();
    io::stdin().read_to_end(&mut file_data)?;

    let mut binwalker = match Binwalk::configure(
        None,
        None,
        args.include,
        args.exclude,
        None,
        false,
    ) {
        Ok(bw) => bw,
        Err(e) => {
            eprintln!("Error configuring Binwalk: {}", e.message);
            std::process::exit(1);
        }
    };

    if args.derived {
        binwalker.enable_derived_streams(true);
    }

    let results = binwalker.analyze_buf(&file_data, "input.bin", false);
    let json_output = serde_json::to_string(&results)?;
    println!("{json_output}");

    Ok(())
}
