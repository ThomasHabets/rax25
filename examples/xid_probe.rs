//! Query advertised XID capabilities without establishing an AX.25 link.
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use rax25::{
    Addr, Packet, PacketType, Xid, r#async::connect_kiss_endpoint, escape, parse_duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const FEND: u8 = 0xc0;
const FESC: u8 = 0xdb;
const MAX_FRAME: usize = 65_536;

#[derive(Debug, Parser)]
struct Opt {
    /// KISS endpoint: `tcp://host:port` or `serial:///dev/ttyUSB0`.
    #[arg(short = 'p')]
    port: String,
    /// Local callsign and SSID.
    #[arg(short = 's')]
    src: String,
    /// Per-attempt and initial connection timeout (nonzero).
    #[arg(long, default_value = "3s", value_parser = positive_duration)]
    timeout: Duration,
    /// Number of retransmissions after the initial query.
    #[arg(long, default_value_t = 3)]
    retries: u32,
    /// Destination callsign and SSID.
    dst: String,
}

fn positive_duration(value: &str) -> Result<Duration> {
    let duration = parse_duration(value)?;
    anyhow::ensure!(!duration.is_zero(), "timeout must be nonzero");
    Ok(duration)
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    let (src, dst) = (Addr::new(&opt.src)?, Addr::new(&opt.dst)?);
    let mut port = tokio::time::timeout(opt.timeout, connect_kiss_endpoint(&opt.port))
        .await
        .context("KISS connection timed out")??;
    let xid = probe(&mut port, &src, &dst, opt.timeout, opt.retries).await?;
    println!("{}", report(&dst, &xid));
    Ok(())
}

#[derive(Default)]
struct Decoder {
    frame: Vec<u8>,
    active: bool,
}

impl Decoder {
    fn push(&mut self, byte: u8) -> Option<Vec<u8>> {
        if byte == FEND {
            let previous = self.active.then(|| std::mem::take(&mut self.frame));
            self.frame.clear();
            self.active = true; // A delimiter also starts the next frame.
            let frame = previous?;
            let mut decoded = Vec::new();
            let mut bytes = frame.into_iter();
            while let Some(byte) = bytes.next() {
                decoded.push(match byte {
                    FESC => match bytes.next()? {
                        0xdc => FEND,
                        0xdd => FESC,
                        _ => return None,
                    },
                    _ => byte,
                });
            }
            return Some(decoded);
        }
        if self.active {
            if self.frame.len() == MAX_FRAME {
                self.frame.clear();
                self.active = false; // Discard oversized frames until FEND.
            } else {
                self.frame.push(byte);
            }
        }
        None
    }
}

fn response(frame: &[u8], local: &Addr, peer: &Addr) -> Result<Option<Xid>> {
    let Some((&command, raw)) = frame.split_first() else {
        return Ok(None);
    };
    if command & 0x0f != 0 || raw.len() < 15 {
        return Ok(None);
    }
    let (Ok(dst), Ok(src)) = (Addr::parse(&raw[..7]), Addr::parse(&raw[7..14])) else {
        return Ok(None);
    };
    if dst.call() != local.call().trim_end_matches("-0")
        || src.call() != peer.call().trim_end_matches("-0")
        || raw[6] & 0x81 != 0 // Destination is not final, and C=0 for responses.
        || raw[13] & 0x80 == 0
    {
        return Ok(None);
    }
    // Validate the complete address chain before using the library parser.
    let mut pos = 14;
    while raw[pos - 1] & 1 == 0 {
        let Some(address) = raw.get(pos..pos + 7) else {
            return Ok(None);
        };
        if Addr::parse(address).is_err() {
            return Ok(None);
        }
        pos += 7;
    }
    let Some(control) = raw.get(pos) else {
        return Ok(None);
    };
    if !matches!(control & !0x10, 0xaf | 0x0f | 0x87) {
        return Ok(None);
    }
    let Ok(packet) = Packet::parse(raw, Some(false)) else {
        return Ok(None);
    };
    match packet.packet_type() {
        PacketType::Xid(xid) if xid.poll => Ok(Some(xid.clone())),
        PacketType::Dm(_) => bail!("peer returned DM (disconnected mode)"),
        PacketType::Frmr(_) => bail!("peer returned FRMR (frame reject)"),
        _ => Ok(None),
    }
}

async fn probe<T: AsyncRead + AsyncWrite + Unpin>(
    port: &mut T,
    local: &Addr,
    peer: &Addr,
    timeout: Duration,
    retries: u32,
) -> Result<Xid> {
    anyhow::ensure!(!timeout.is_zero(), "timeout must be nonzero");
    let query =
        escape(&Packet::xid(local.clone(), peer.clone(), true, true, None).serialize(false));
    let mut decoder = Decoder::default();
    for attempt in 0..=retries {
        let result = tokio::time::timeout(timeout, async {
            port.write_all(&query).await.context("writing XID query")?;
            port.flush().await.context("flushing XID query")?;
            let mut buffer = [0; 1024];
            loop {
                let count = port
                    .read(&mut buffer)
                    .await
                    .context("reading KISS endpoint")?;
                anyhow::ensure!(count != 0, "KISS endpoint closed (EOF)");
                for &byte in &buffer[..count] {
                    if let Some(frame) = decoder.push(byte)
                        && let Some(xid) = response(&frame, local, peer)?
                    {
                        return Ok(xid);
                    }
                }
            }
        })
        .await;
        match result {
            Ok(result) => return result,
            Err(_) if attempt < retries => {}
            Err(_) => bail!("XID timed out after {} attempts", u64::from(retries) + 1),
        }
    }
    unreachable!("the last attempt always returns")
}

fn flags(value: Option<u32>, width: usize, names: &[(u32, &str)]) -> String {
    value.map_or_else(
        || "omitted".into(),
        |bits| {
            let labels: Vec<_> = names
                .iter()
                .filter(|(mask, _)| bits & mask != 0)
                .map(|(_, name)| *name)
                .collect();
            format!("0x{bits:0width$x} [{}]", labels.join(", "))
        },
    )
}

fn report(peer: &Addr, xid: &Xid) -> String {
    let Some(p) = &xid.parameters else {
        return format!(
            "{} advertised XID: no information field (no parameters supplied)",
            peer.call()
        );
    };
    let classes = flags(
        p.classes.map(u32::from),
        4,
        &[(1, "ABM"), (0x20, "half duplex"), (0x40, "full duplex")],
    );
    let functions = flags(
        p.optional_functions,
        6,
        &[
            (2, "REJ"),
            (4, "SREJ"),
            (0x80, "extended addressing"),
            (0x400, "modulo-8"),
            (0x800, "modulo-128"),
            (0x2000, "TEST"),
            (0x8000, "16-bit FCS"),
            (0x2_0000, "synchronous transmit"),
            (0x20_0000, "multi-frame SREJ"),
            (0x40_0000, "segmenter"),
        ],
    );
    let size = p.receive_length_bits.map_or_else(
        || "omitted".into(),
        |n| format!("{n} bits ({} whole bytes)", n / 8),
    );
    let number = |n: Option<u32>| n.map_or_else(|| "omitted".into(), |n| n.to_string());
    format!(
        "{} advertised XID (not negotiated):\nClasses: {classes}\nOptional functions: {functions}\nReceive size: {size}\nReceive window: {}\nAcknowledgement timer (ms): {}\nRetries: {}\nOmitted parameters are not inferred. Explicit zero-length fields/groups use the codec's AX.25 defaults.",
        peer.call(),
        number(p.receive_window.map(u32::from)),
        number(p.acknowledgement_timer_ms),
        number(p.retries.map(u32::from))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rax25::xid::XidParameters;
    use tokio::io::{DuplexStream, duplex};

    fn addresses() -> (Addr, Addr) {
        (Addr::new("LOCAL-1").unwrap(), Addr::new("PEER-2").unwrap())
    }
    async fn query(server: &mut DuplexStream) {
        let (local, peer) = addresses();
        let expected = escape(&Packet::xid(local, peer, true, true, None).serialize(false));
        let mut actual = vec![0; expected.len()];
        server.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected); // Only an information-free XID, never SABM.
    }
    fn reply(parameters: Option<XidParameters>) -> Vec<u8> {
        let (local, peer) = addresses();
        Packet::xid(peer, local, false, true, parameters).serialize(false)
    }

    async fn run(client: &mut DuplexStream, milliseconds: u64, retries: u32) -> Result<Xid> {
        let (local, peer) = addresses();
        let timeout = Duration::from_millis(milliseconds);
        tokio::time::timeout(
            Duration::from_secs(1),
            probe(client, &local, &peer, timeout, retries),
        )
        .await
        .expect("probe exceeded outer deadline")
    }

    #[test]
    fn cli_and_advertised_output() {
        assert!(Opt::try_parse_from(["probe", "-s", "LOCAL", "PEER"]).is_err());
        let args = "probe -p tcp://localhost:1 -s LOCAL PEER";
        let opt = Opt::try_parse_from(args.split_whitespace()).unwrap();
        assert!(positive_duration("0").is_err());
        assert_eq!(opt.timeout, Duration::from_secs(3));
        assert_eq!(opt.retries, 3);
        let (_, peer) = addresses();
        let mut xid = Xid {
            poll: true,
            parameters: None,
        };
        assert!(report(&peer, &xid).contains("no information field"));
        xid.parameters = Some(XidParameters {
            classes: Some(0x21),
            optional_functions: Some(0x800),
            ..XidParameters::default()
        });
        let output = report(&peer, &xid);
        for text in "advertised|not negotiated|0x0021|half duplex|0x000800|modulo-128|Receive size: omitted|Retries: omitted".split('|') {
            assert!(output.contains(text), "{output}");
        }
    }

    #[tokio::test]
    async fn filters_and_decodes_split_escaped_shared_frames() {
        let (mut client, mut server) = duplex(2048);
        let task = tokio::spawn(async move {
            query(&mut server).await;
            let (local, peer) = addresses();
            let other = Addr::new("OTHER").unwrap();
            let mut wire = vec![9, FEND, FEND, 0, FESC, 7, FEND, 0, FESC, FEND];
            for packet in [
                Packet::xid(other.clone(), local.clone(), false, true, None),
                Packet::xid(peer.clone(), other, false, true, None),
                Packet::xid(peer.clone(), local.clone(), true, true, None),
                Packet::xid(peer.clone(), local.clone(), false, false, None),
            ] {
                wire.extend_from_slice(&escape(&packet.serialize(false))[1..]);
            }
            let mut nondata = escape(&reply(None));
            nondata[1] = 1;
            wire.extend(nondata);
            let parameters = XidParameters {
                receive_length_bits: Some(0xc0db),
                retries: Some(7),
                ..XidParameters::default()
            };
            wire.extend_from_slice(&escape(&reply(Some(parameters)))[1..]);
            for byte in wire {
                server.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let xid = run(&mut client, 500, 0).await.unwrap();
        assert_eq!(xid.parameters.unwrap().receive_length_bits, Some(0xc0db));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn retries_are_retransmissions() {
        let (mut client, mut server) = duplex(1024);
        let task = tokio::spawn(async move {
            for _ in 0..3 {
                query(&mut server).await;
            }
            server.write_all(&escape(&reply(None))).await.unwrap();
        });
        assert!(run(&mut client, 20, 2).await.unwrap().parameters.is_none());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn eof_and_peer_rejections_are_not_retried() {
        for control in [None, Some(0x1f), Some(0x97)] {
            let (mut client, mut server) = duplex(1024);
            let task = tokio::spawn(async move {
                query(&mut server).await;
                if let Some(control) = control {
                    let mut raw = reply(None);
                    raw[14] = control;
                    server.write_all(&escape(&raw)).await.unwrap();
                }
            });
            let error = run(&mut client, 5000, 3).await.unwrap_err();
            assert!(error.to_string().contains(match control {
                None => "EOF",
                Some(0x1f) => "DM",
                _ => "FRMR",
            }));
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn timeout_bounds_reads_and_blocked_writes() {
        for capacity in [1, 1024] {
            let (mut client, _server) = duplex(capacity);
            let error = run(&mut client, 10, 0).await.unwrap_err();
            assert!(error.to_string().contains("after 1 attempts"));
        }
    }

    #[test]
    fn malformed_frames_are_bounded_and_safe() {
        let mut decoder = Decoder::default();
        decoder.push(FEND);
        for _ in 0..MAX_FRAME + 100 {
            decoder.push(1);
            assert!(decoder.frame.len() <= MAX_FRAME);
        }
        decoder.push(FEND);
        assert_eq!(decoder.push(0), None);
        assert_eq!(decoder.push(FEND), Some(vec![0]));
        let (local, peer) = addresses();
        let raw = Packet::xid(peer.clone(), local.clone(), false, true, None).serialize(false);
        for length in 0..raw.len() {
            assert!(
                response(&[&[0], &raw[..length]].concat(), &local, &peer)
                    .unwrap()
                    .is_none()
            );
        }
        for control in 0..=255 {
            let mut malformed = raw.clone();
            malformed[13] &= !1;
            malformed[14] = control;
            assert!(
                response(&[&[0], malformed.as_slice()].concat(), &local, &peer)
                    .unwrap()
                    .is_none()
            );
        }
    }
}
