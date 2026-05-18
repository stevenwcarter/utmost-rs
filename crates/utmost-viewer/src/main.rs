use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "Replay a utmost carve event log")]
struct Args {
    /// Path to either a directory or a carve_events.bin file
    target: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    utmost_gui::run_from_file(&args.target)
}
