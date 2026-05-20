use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "Browse one or more utmost carve event logs")]
struct Args {
    /// Path to either a directory (scanned recursively for <stem>-events.bin
    /// files; each becomes a row on the case-selection screen) or a single
    /// <stem>-events.bin file.
    target: PathBuf,

    /// Search location(s) for the original source image. May be a file (used
    /// directly if its basename matches a recorded source) or a directory
    /// (scanned by basename). May be repeated; entries are tried left to
    /// right. If omitted, the viewer falls back to the path recorded in the
    /// event log and then to the parent of the log's directory.
    #[arg(long, action = clap::ArgAction::Append)]
    source: Vec<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let cases = utmost_gui::discover_cases(&args.target)?;
    utmost_gui::run_picker(
        cases
            .into_iter()
            .map(utmost_gui::case::CaseSource::Historical)
            .collect(),
        args.source,
    )
}
