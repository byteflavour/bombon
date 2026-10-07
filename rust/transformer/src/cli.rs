use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

use crate::transform::{Options, transform};

#[derive(Parser)]
pub struct Cli {
    /// Include buildtime dependencies in output
    #[arg(long)]
    include_buildtime_dependencies: bool,

    /// Regex pattern of store paths to exclude from the final SBOM.
    ///
    /// Can be given multiple times to exclude multiple patterns.
    #[arg(short, long)]
    exclude: Vec<String>,

    /// Data to derive the serial number of the SBOM from.
    ///
    /// The same seed always yields the same serial number.
    #[arg(long)]
    serial_number_seed: String,

    /// Path to JSON containing the build recipes of the target
    #[arg(long)]
    recipes: PathBuf,

    /// Path to JSON containing the metadata of packages that are built from the same source as
    /// a build recipe of the target
    #[arg(long)]
    same_source_metadata: PathBuf,

    /// Name to describe the target derivation with instead of its own
    #[arg(long)]
    subject_name: Option<String>,

    /// Version to describe the target derivation with instead of its own
    #[arg(long)]
    subject_version: Option<String>,

    /// Store path that is part of what the SBOM describes besides the target derivation.
    ///
    /// Can be given multiple times.
    #[arg(long)]
    extra_path: Vec<String>,

    /// Path to target derivation
    target: String,

    /// Path to JSON containing the buildtime input
    buildtime_input: PathBuf,

    /// Path to a newline separated .txt file containing the runtime input
    runtime_input: PathBuf,

    /// Path to write the SBOM to
    output: PathBuf,
}

impl Cli {
    pub fn call(self) -> Result<()> {
        transform(&Options {
            include_buildtime_dependencies: self.include_buildtime_dependencies,
            exclude: self.exclude,
            serial_number_seed: self.serial_number_seed,
            recipes: self.recipes,
            same_source_metadata: self.same_source_metadata,
            subject_name: self.subject_name,
            subject_version: self.subject_version,
            extra_paths: self.extra_path,
            target: self.target,
            buildtime_input: self.buildtime_input,
            runtime_input: self.runtime_input,
            output: self.output,
        })
    }
}
