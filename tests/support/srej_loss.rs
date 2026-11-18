//! Deterministic loss at the KISS boundary, retaining the real audio path.
use std::collections::HashSet;
use std::fs::File;
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use rax25::pcap::PcapWriter;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

async fn forward(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    dir: &Path,
    name: &str,
    extended: bool,
    loss: bool,
) -> Result<()> {
    let mut capture = PcapWriter::create(dir.join(format!("{name}.pcap")))?;
    let mut log = File::create(dir.join(format!("{name}.log")))?;
    let mut dropped = HashSet::new();
    let mut frame = Vec::new();
    let mut buf = [0; 4096];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        for &byte in &buf[..n] {
            if byte != 0xc0 {
                frame.push(byte);
                continue;
            }
            if frame.is_empty() {
                continue;
            }
            if frame[0] != 0 {
                // Hardware status must reach the client even when data is
                // dropped; it is not an AX.25 frame and has no place in pcap.
                writer.write_all(&[0xc0]).await?;
                writer.write_all(&frame).await?;
                writer.write_all(&[0xc0]).await?;
                frame.clear();
                continue;
            }
            let decoded = rax25::unescape(&frame[1..])?;
            let packet = rax25::Packet::parse(&decoded, Some(extended))?;
            capture.write(&decoded)?;
            let drop = if let rax25::PacketType::Iframe(p) = packet.packet_type() {
                loss && matches!(p.ns, 1 | 2) && dropped.insert(p.ns)
            } else {
                false
            };
            let description = match packet.packet_type() {
                rax25::PacketType::Iframe(p) => {
                    format!("I N(S)={} N(R)={} len={}", p.ns, p.nr, p.payload.len())
                }
                other => format!("{other:?}"),
            };
            writeln!(log, "{} {description}", if drop { "DROP" } else { "PASS" })?;
            log.flush()?;
            if !drop {
                writer.write_all(&[0xc0]).await?;
                writer.write_all(&frame).await?;
                writer.write_all(&[0xc0]).await?;
            }
            frame.clear();
        }
    }
}

pub async fn proxy(
    local: TcpStream,
    modem: TcpStream,
    dir: &Path,
    extended: bool,
    loss: bool,
) -> Result<()> {
    let (lr, lw) = local.into_split();
    let (mr, mw) = modem.into_split();
    tokio::try_join!(
        forward(lr, mw, dir, "to-direwolf", extended, loss),
        forward(mr, lw, dir, "from-direwolf", extended, loss)
    )?;
    Ok(())
}

pub fn verify(dir: &Path, extended: bool, srej: bool) -> Result<()> {
    for name in ["to-direwolf", "from-direwolf"] {
        let log = std::fs::read_to_string(dir.join(format!("{name}.log")))?;
        ensure!(
            log.lines().filter(|line| line.starts_with("DROP")).count() == 2,
            "{name}: loss scenario not exercised\n{log}"
        );
        let bytes = std::fs::read(dir.join(format!("{name}.pcap")))?;
        let mut remaining = bytes.get(24..).context("missing capture header")?;
        let mut requests = Vec::new();
        let mut sequence_counts = [0_u32; 128];
        while !remaining.is_empty() {
            let header = remaining.get(..16).context("truncated record")?;
            let size = usize::try_from(u32::from_le_bytes(header[8..12].try_into()?))?;
            let frame = remaining.get(16..16 + size).context("truncated frame")?;
            let control = frame[14];
            if control & 3 == 1 {
                requests.push((control & 0xf, frame.len() > if extended { 16 } else { 15 }));
            }
            if control & 1 == 0 {
                let packet = rax25::Packet::parse(frame, Some(extended))?;
                if let rax25::PacketType::Iframe(p) = packet.packet_type()
                    && p.payload.len() == 32
                    && p.payload[0] % 32 == 0
                    && p.payload
                        .iter()
                        .copied()
                        .eq(p.payload[0]..=p.payload[0] + 31)
                {
                    // Identify the first burst by payload, not ACK-dependent
                    // window boundaries or modulo-8 sequence reuse later on.
                    sequence_counts[usize::from(p.ns)] += 1;
                }
            }
            remaining = &remaining[16 + size..];
        }
        if srej {
            ensure!(
                requests.contains(&(0xd, true)),
                "{name}: no multi-frame SREJ\n{log}"
            );
            ensure!(
                !requests.iter().any(|(code, _)| *code == 9),
                "{name}: unexpected REJ\n{log}"
            );
            for ns in [1, 2] {
                ensure!(
                    sequence_counts[ns] >= 2,
                    "{name}: missing selective retransmission of {ns}\n{log}"
                );
            }
            for ns in [0, 3] {
                ensure!(
                    sequence_counts[ns] == 1,
                    "{name}: unnecessarily retransmitted {ns}\n{log}"
                );
            }
        } else {
            ensure!(
                requests.iter().any(|(code, _)| *code == 9),
                "{name}: no REJ recovery\n{log}"
            );
            ensure!(
                !requests.iter().any(|(code, _)| *code == 0xd),
                "{name}: SREJ despite opt-out\n{log}"
            );
        }
    }
    Ok(())
}
