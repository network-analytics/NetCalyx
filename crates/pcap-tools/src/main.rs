// Copyright (C) 2026-present The NetCalyx Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod commands;

use clap::Parser;
use commands::Command;
use shadow_rs::shadow;
use std::process::ExitCode;

shadow!(build);

/// Builds the multi-line version/build info string
fn version_info() -> String {
    format!(
        "{}\n  \
         Commit:      {} ({})\n  \
         Branch/Tag:  {} / {}\n  \
         Build Time:  {}\n  \
         Rust:        {} ({})\n  \
         OS:          {}",
        build::PKG_VERSION,
        build::COMMIT_HASH,
        build::COMMIT_DATE,
        build::BRANCH,
        build::TAG,
        build::BUILD_TIME,
        build::RUST_VERSION,
        build::BUILD_RUST_CHANNEL,
        build::BUILD_OS,
    )
}

#[derive(Debug, Parser)]
#[command(
    about,
    long_about = None,
    disable_version_flag = true,
    version = version_info()
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Print version and build information, then exit
    #[arg(long, short = 'V', action = clap::ArgAction::Version)]
    version: Option<bool>,
}

fn main() -> ExitCode {
    Cli::parse().command.run()
}
