mod buildtime_input;
mod cli;
mod cyclonedx;
mod derivation;
mod hash;
mod recipe;
mod runtime_input;
mod transform;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, RecipeIndexCli};

fn main() -> Result<()> {
    if std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == "recipe-index")
    {
        RecipeIndexCli::parse_from(std::env::args_os().skip(1)).call()
    } else {
        Cli::parse().call()
    }
}
