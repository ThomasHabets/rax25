//! pcap writer
//!
//! The pcap format is very simple, so no need for an external crate or linking
//! to libpcap.
//!
//! This implementation writes little endian pcap files on all platforms.
//!
//! Useful resources:
//! * https://wiki.wireshark.org/Development/LibpcapFileFormat
//! * https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html
//! * https://www.tcpdump.org/linktypes.html

use std::io::BufWriter;
use std::io::Write;

use anyhow::Result;

// Little endian magic.
const MAGIC: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1];
const VERSION_MAJOR: u16 = 2;
const VERSION_MINOR: u16 = 4;
const LINKTYPE_AX25: u32 = 3;

fn write_u16(mut w: impl std::io::Write, v: u16) -> Result<()> {
    w.write_all(&[(v & 0xff) as u8, ((v >> 8) & 0xFF) as u8])?;
    Ok(())
}

fn write_u32(mut w: impl std::io::Write, v: u32) -> Result<()> {
    w.write_all(&[
        (v & 0xff) as u8,
        ((v >> 8) & 0xFF) as u8,
        ((v >> 16) & 0xFF) as u8,
        ((v >> 24) & 0xFF) as u8,
    ])?;
    Ok(())
}

/// PcapWriter writes AX.25 pcap files.
///
/// It writes them buffered, for efficiency, so a crash could lose the last
/// packets.
pub struct PcapWriter {
    f: BufWriter<std::fs::File>,
}

impl PcapWriter {
    /// Create a new pcap file. Fails if the file already exists.
    pub fn create(filename: std::path::PathBuf) -> Result<Self> {
        let mut f = BufWriter::new(
            std::fs::File::options()
                .read(false)
                .write(true)
                .create_new(true)
                .open(filename)?,
        );
        f.write_all(&MAGIC)?;
        write_u16(&mut f, VERSION_MAJOR)?;
        write_u16(&mut f, VERSION_MINOR)?;

        // GMT offset. In theory this is i32 (not u32) GMT offset of all other
        // timestamps in the file. In practice, who put anything but UTC
        // timestamps in files?
        //
        // Actually, here's an idea: Buy another 32 bits of epoch offset, by
        // using this field. "My time zone is offset from UTC by 68 years?
        //
        // Not sure what read tooling would support that though. My testing
        // shows that wireshark seems to assume the closest wrap to today,
        // because adding 20 years from today (2024) does show timestamps as
        // being in 2044 in tshark -V.
        write_u32(&mut f, 0)?;

        // Time source accuracy. All tools set zero.
        write_u32(&mut f, 0)?;

        // Snaplen. This implementation simply captures the whole packets. And
        // because it's AX.25 packets are more like 200 bytes.
        //
        // Apparently 65535 is a normal value to use.
        write_u32(&mut f, 65535)?;

        // Another option is LINKTYPE_AX25_KISS. But currently we have nothing
        // interesting to populate there, so just using LINKTYPE_AX25 for now.
        //
        // Here's also where some FCS bits could be set, but we're currently
        // running without FCS.
        write_u32(&mut f, LINKTYPE_AX25)?;
        Ok(Self { f })
    }

    /// Write a blob as a new packet entry.
    ///
    /// If this write fails, no further writes can be made, as the added record
    /// is now only partially added.
    pub fn write(&mut self, packet: &[u8]) -> Result<()> {
        let len = packet.len() as u32;
        let now = std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH)?;
        // TODO: Ugh, the pcap format is not Y2036 safe. What do we do here?
        write_u32(&mut self.f, now.as_secs() as u32)?;
        write_u32(&mut self.f, (now.as_micros() % 1000000) as u32)?;
        write_u32(&mut self.f, len)?;
        write_u32(&mut self.f, len)?;
        self.f.write_all(packet)?;
        Ok(())
    }
}
/* vim: textwidth=80
 */
