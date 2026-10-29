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

use clap::Args;
use netcalyx_pcap_tools::bmp::{BmpValidator, bmp_message_len};
use netcalyx_pcap_tools::tcp_split::split_tcp_messages;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Args)]
pub struct BmpSplitArgs {
    /// Input PCAP or PCAPNG file path
    #[clap(short, long)]
    input: PathBuf,

    /// Output PCAP file path
    #[clap(short, long)]
    output: PathBuf,

    /// BMP collector destination ports (comma-separated, example:
    /// 1790,11019)
    #[clap(long, value_delimiter = ',', required = true)]
    ports: Vec<u16>,

    /// Destination port written in the output packets
    #[clap(long, default_value_t = 1790)]
    rewrite_port: u16,

    /// Decode every extracted message and report parsing errors
    #[clap(long, default_value_t = false)]
    validate: bool,
}

impl BmpSplitArgs {
    pub fn run(self) -> ExitCode {
        let mut validator = BmpValidator::default();
        let mut invalid = 0usize;
        let result = split_tcp_messages(
            &self.input,
            &self.output,
            &self.ports,
            Some(self.rewrite_port),
            bmp_message_len,
            |flow, frame, msg| {
                if self.validate
                    && let Err(err) = validator.validate(flow, msg)
                {
                    invalid += 1;
                    eprintln!("frame {frame}: flow {flow:?}: invalid BMP message: {err:?}");
                }
            },
        );
        match result {
            Ok(stats) => {
                for (flow, len) in &stats.incomplete_flows {
                    eprintln!(
                        "warning: flow {flow:?} has {len} trailing bytes not forming a complete BMP message, dropped"
                    );
                }
                eprintln!(
                    "read {} frames, dropped {} duplicate TCP segments, wrote {} BMP messages in {} packets to {}",
                    stats.frames_in,
                    stats.duplicate_segments,
                    stats.messages_out,
                    stats.packets_out,
                    self.output.display()
                );
                if invalid > 0 {
                    eprintln!("{invalid} messages failed validation");
                    return ExitCode::FAILURE;
                }
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::FAILURE
            }
        }
    }
}
