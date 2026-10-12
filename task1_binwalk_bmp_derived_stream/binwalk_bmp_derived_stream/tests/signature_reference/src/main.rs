use binwalk::Binwalk;
use clap::Parser;
use std::io::{self, Read};

#[derive(Parser)]
struct Args {
    #[arg(short = 'y', value_delimiter = ',')]
    include: Option<Vec<String>>,
    #[arg(short = 'x', value_delimiter = ',')]
    exclude: Option<Vec<String>>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data)?;
    let scanner = Binwalk::configure(None, None, args.include, args.exclude, None, false)
        .map_err(|e| io::Error::other(e.message))?;
    println!("{}", serde_json::to_string(&scanner.scan(&data))?);
    Ok(())
}
