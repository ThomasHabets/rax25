//! Streaming AX.25 pcapng capture with direction and packet comments.
use std::io::Write;

use crate::Result;

/// Direction relative to the application connected to a KISS modem.
#[derive(Clone, Copy)]
pub enum Direction {
    /// Application to modem.
    Tx,
    /// Modem to application.
    Rx,
}

/// Writes complete AX.25 frames without KISS framing or FCS.
pub struct PcapNgWriter<W: Write> {
    output: W,
}

fn option(body: &mut Vec<u8>, code: u16, value: &[u8]) -> Result<()> {
    body.extend(code.to_le_bytes());
    body.extend(u16::try_from(value.len())?.to_le_bytes());
    body.extend(value);
    body.resize(body.len().next_multiple_of(4), 0);
    Ok(())
}

impl<W: Write> PcapNgWriter<W> {
    /// Write a section header and named TX/RX interface descriptions.
    pub fn new(output: W) -> Result<Self> {
        let mut writer = Self { output };
        let mut header = Vec::from(0x1a2b_3c4d_u32.to_le_bytes());
        header.extend(1_u16.to_le_bytes());
        header.extend(0_u16.to_le_bytes());
        header.extend(u64::MAX.to_le_bytes());
        writer.block(0x0a0d_0d0a, &header)?;
        for name in [b"TX", b"RX"] {
            let mut interface = Vec::from(3_u16.to_le_bytes());
            interface.extend(0_u16.to_le_bytes());
            interface.extend(u32::MAX.to_le_bytes());
            option(&mut interface, 2, name)?;
            option(&mut interface, 0, &[])?;
            writer.block(1, &interface)?;
        }
        Ok(writer)
    }

    fn block(&mut self, kind: u32, body: &[u8]) -> Result<()> {
        let size = u32::try_from(body.len() + 12)?;
        self.output.write_all(&kind.to_le_bytes())?;
        self.output.write_all(&size.to_le_bytes())?;
        self.output.write_all(body)?;
        self.output.write_all(&size.to_le_bytes())?;
        self.output.flush()?;
        Ok(())
    }

    /// Record a packet, adding the exact comment `dropped` if discarded.
    pub fn write(&mut self, packet: &[u8], direction: Direction, dropped: bool) -> Result<()> {
        let timestamp = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_micros(),
        )?;
        let (interface, flags) = match direction {
            Direction::Tx => (0_u32, 2_u32),
            Direction::Rx => (1_u32, 1_u32),
        };
        let length = u32::try_from(packet.len())?;
        let mut body = Vec::new();
        body.extend(interface.to_le_bytes());
        body.extend(u32::try_from(timestamp >> 32)?.to_le_bytes());
        body.extend(u32::try_from(timestamp & 0xffff_ffff)?.to_le_bytes());
        body.extend(length.to_le_bytes());
        body.extend(length.to_le_bytes());
        body.extend(packet);
        body.resize(body.len().next_multiple_of(4), 0);
        option(&mut body, 2, &flags.to_le_bytes())?;
        if dropped {
            option(&mut body, 1, b"dropped")?;
        }
        option(&mut body, 0, &[])?;
        self.block(6, &body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tshark_reads_directions_and_dropped_comments() -> Result<()> {
        use std::process::{Command, Stdio};
        let mut writer = PcapNgWriter::new(Vec::new())?;
        let packet = crate::Packet::ui(
            crate::Callsign::new("LOCAL")?,
            crate::Callsign::new("REMOTE")?,
            vec![1, 2, 3],
        )
        .serialize();
        writer.write(&packet, Direction::Tx, true)?;
        writer.write(&packet, Direction::Rx, true)?;
        writer.write(&packet, Direction::Rx, false)?;
        let mut child = Command::new("tshark")
            .args([
                "-r",
                "-",
                "-T",
                "fields",
                "-e",
                "frame.interface_name",
                "-e",
                "frame.comment",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child.stdin.take().unwrap().write_all(&writer.output)?;
        let result = child.wait_with_output()?;
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&result.stdout),
            "TX\tdropped\nRX\tdropped\nRX\t\n"
        );
        Ok(())
    }
}
