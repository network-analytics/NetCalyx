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

//! Minimal legacy PCAP (microsecond resolution) writer.

use pcap_parser::{LegacyPcapBlock, Linktype, PcapHeader, ToVec};
use std::io::{self, Write};
use std::time::Duration;

const SNAPLEN: u32 = 262_144;

/// Writes frames to a legacy PCAP file. The file header is emitted lazily
/// with the link type of the first written frame, all frames must share it.
pub struct LegacyPcapWriter<W: Write> {
    inner: W,
    link_type: Option<Linktype>,
}

impl<W: Write> LegacyPcapWriter<W> {
    pub const fn new(inner: W) -> Self {
        Self {
            inner,
            link_type: None,
        }
    }

    pub fn write_frame(
        &mut self,
        link_type: Linktype,
        timestamp: Duration,
        data: &[u8],
    ) -> io::Result<()> {
        match self.link_type {
            None => self.write_header(link_type)?,
            Some(current) if current != link_type => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "legacy pcap supports a single link type, got {link_type:?} after {current:?}"
                    ),
                ));
            }
            Some(_) => {}
        }
        let len = u32::try_from(data.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
        let block = LegacyPcapBlock {
            ts_sec: u32::try_from(timestamp.as_secs()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "timestamp out of range")
            })?,
            ts_usec: timestamp.subsec_micros(),
            caplen: len,
            origlen: len,
            data,
        };
        self.inner.write_all(&block.to_vec_raw().map_err(gen_err)?)
    }

    /// Flush and return the inner writer, emitting an (Ethernet) header if no
    /// frame was written so the output is still a valid PCAP file.
    pub fn finish(mut self) -> io::Result<W> {
        if self.link_type.is_none() {
            self.write_header(Linktype::ETHERNET)?;
        }
        self.inner.flush()?;
        Ok(self.inner)
    }

    fn write_header(&mut self, link_type: Linktype) -> io::Result<()> {
        let header = PcapHeader {
            snaplen: SNAPLEN,
            network: link_type,
            ..PcapHeader::new()
        };
        self.inner
            .write_all(&header.to_vec_raw().map_err(gen_err)?)?;
        self.link_type = Some(link_type);
        Ok(())
    }
}

fn gen_err<E: std::fmt::Debug>(err: E) -> io::Error {
    io::Error::other(format!("{err:?}"))
}
