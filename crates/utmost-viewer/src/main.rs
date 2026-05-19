use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "Replay a utmost carve event log")]
struct Args {
    /// Path to either a directory or a carve_events.bin file.
    target: PathBuf,

    /// Search location for the original source image. May be a file (used
    /// directly if its basename matches a recorded source) or a directory
    /// (scanned by basename). May be repeated; entries are tried left to
    /// right. If omitted, the viewer falls back to the path recorded in
    /// the event log and then to the parent of the log's directory.
    #[arg(long, action = clap::ArgAction::Append)]
    source: Vec<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    utmost_gui::run_from_file(&args.target, args.source)
}
