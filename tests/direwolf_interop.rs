//! Opt-in, real Bell 202 audio interop with the installed Dire Wolf binary.
//! Run with `tests/run_direwolf_interop.sh`, or provide `BELL202_BIN` and a live
//! Pulse server. Dependency installation belongs to the launcher, not the test.
//! No Dire Wolf source or dependencies are copied into this repository.
#![cfg(feature = "async")]

use std::fmt::Write as _;
use std::fs::{self, File};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agw::r#async::AGWServer;
use agw::{Call, Packet, Pid, Port};
use anyhow::{Context, Result, bail, ensure};
use rax25::Callsign;
use rax25::r#async::{ConnectionBuilder, PortType};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

const DEADLINE: Duration = Duration::from_secs(30);

struct Modem {
    binary: PathBuf,
    busy: bool,
}

impl Modem {
    fn command(&self, port: u16) -> Command {
        let mut command = Command::new(&self.binary);
        command.args([
            "--audio",
            "--audio-input",
            "from-direwolf",
            "--audio-output",
            "to-direwolf",
            "--audio-rate",
            "48000",
            "--tcp-listen",
            &format!("127.0.0.1:{port}"),
        ]);
        if self.busy {
            command.arg("--busy-threshold-db=-30");
        }
        command
    }

    fn retry(&self, files: bool) -> u64 {
        if self.busy {
            3
        } else if files {
            45
        } else {
            5
        }
    }

    fn window(&self, files: bool) -> u8 {
        if self.busy {
            if files { 16 } else { 8 }
        } else {
            4
        }
    }
}

#[test]
fn modem_profiles_keep_legacy_modems_conservative() {
    for busy in [false, true] {
        let modem = Modem {
            binary: PathBuf::from("bell202"),
            busy,
        };
        assert_eq!(modem.retry(false), if busy { 3 } else { 5 });
        assert_eq!(modem.retry(true), if busy { 3 } else { 45 });
        assert_eq!(modem.window(false), if busy { 8 } else { 4 });
        assert_eq!(modem.window(true), if busy { 16 } else { 4 });
        assert_eq!(
            modem
                .command(8000)
                .get_args()
                .any(|arg| arg == "--busy-threshold-db=-30"),
            busy
        );
    }
}

#[path = "support/srej_loss.rs"]
mod srej_loss;

fn manifest_dir() -> Result<PathBuf> {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .context("CARGO_MANIFEST_DIR must be set when running the interop test")
}

struct Harness {
    dir: PathBuf,
    children: Vec<Child>,
    modules: Vec<String>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        for child in self.children.iter_mut().rev() {
            let _ = child.kill();
            let _ = child.wait();
        }
        for id in self.modules.iter().rev() {
            let _ = Command::new("pactl")
                .args(["unload-module", id])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

fn report_case(case: &str, harness: &Harness, result: Result<()>) -> Result<()> {
    eprintln!(
        "[{case}] {} artifacts: {}",
        if result.is_ok() { "PASS" } else { "FAIL" },
        harness.dir.display()
    );
    result.with_context(|| format!("{case}: interop artifacts: {}", harness.dir.display()))
}

fn selective_harness(extended: bool, srej: Option<bool>) -> Result<(String, Harness)> {
    let case = format!(
        "direwolf_{}_{}_audio",
        if extended { "extended" } else { "standard" },
        if srej == Some(true) { "srej" } else { "rej" }
    );
    let harness = Harness::new(
        extended,
        None,
        &case,
        "XID after connect; scripted TX/RX drops of I frames N(S)=1,2; 256-byte recovery payload",
    )?;
    Ok((case, harness))
}

fn random_harness(extended: bool, percent: u8, files: bool) -> Result<(&'static str, Harness)> {
    let case = if files && extended {
        "direwolf_lossy_file_transfer_extended_srej"
    } else if files {
        "direwolf_lossy_file_transfer"
    } else if extended {
        "direwolf_extended_audio"
    } else {
        "direwolf_standard_audio"
    };
    let loss = format!(
        "random TX/RX loss {percent}%, seed 123; {}",
        if files && extended {
            "4 KiB upload/echo download, XID-negotiated multi-SREJ"
        } else if files {
            "4 KiB upload/echo download, REJ, no XID"
        } else {
            "small echo, no XID"
        }
    );
    Ok((case, Harness::new(extended, Some(percent), case, &loss)?))
}

impl Harness {
    fn new(extended: bool, drop_percent: Option<u8>, case: &str, loss: &str) -> Result<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let id = format!("{}_{}_{}", std::process::id(), nonce, extended);
        let root = manifest_dir()?;
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map_or_else(|| root.join("target"), |path| root.join(path));
        let profile = drop_percent.map_or_else(
            || "scripted-loss".to_owned(),
            |percent| format!("random-loss{percent}"),
        );
        let dir = target
            .join("direwolf_interop")
            .join(format!("{case}-{profile}-{id}"));
        fs::create_dir_all(&dir)?;
        let mode = if extended { "modulo-128" } else { "modulo-8" };
        eprintln!(
            "[{case}] START {mode}; {loss}\n[{case}] artifacts: {}",
            dir.display()
        );
        let mut harness = Self {
            dir,
            children: Vec::new(),
            modules: Vec::new(),
        };
        let mut config = String::from("</usr/share/alsa/alsa.conf>\n");
        for (sink, input, output) in [
            (format!("rax25_to_dw_{id}"), "from-bell202", "to-direwolf"),
            (format!("rax25_from_dw_{id}"), "from-direwolf", "to-bell202"),
        ] {
            let result = Command::new("pactl")
                .args([
                    "load-module",
                    "module-null-sink",
                    &format!("sink_name={sink}"),
                    "rate=48000",
                    "channels=1",
                    "channel_map=mono",
                ])
                .output()
                .context("pactl is required; run tests/run_direwolf_interop.sh")?;
            fs::write(
                harness.dir.join(format!("pactl-{input}.log")),
                &result.stderr,
            )?;
            ensure!(
                result.status.success(),
                "cannot create Pulse sink: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            let module = String::from_utf8(result.stdout)?.trim().to_owned();
            ensure!(!module.is_empty(), "pactl returned no module ID");
            harness.modules.push(module);
            write!(
                config,
                "pcm.{input} {{ type pulse device \"{sink}.monitor\" hint {{ show on description \"{input}\" }} }}\n\
                 pcm.{output} {{ type pulse device \"{sink}\" hint {{ show on description \"{output}\" }} }}\n"
            )?;
        }
        fs::write(harness.dir.join("alsa.conf"), config)?;
        Ok(harness)
    }

    fn spawn(&mut self, name: &str, command: &mut Command) -> Result<()> {
        let stdout = File::create(self.dir.join(format!("{name}.stdout.log")))?;
        let stderr = File::create(self.dir.join(format!("{name}.stderr.log")))?;
        command
            .env("ALSA_CONFIG_PATH", self.dir.join("alsa.conf"))
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr);
        self.children.push(
            command
                .spawn()
                .with_context(|| format!("starting {name}"))?,
        );
        Ok(())
    }

    fn check_children(&mut self) -> Result<()> {
        for child in &mut self.children {
            if let Some(status) = child.try_wait()? {
                bail!(
                    "interop child exited with {status}; inspect {}",
                    self.dir.display()
                );
            }
        }
        Ok(())
    }

    async fn connect(&mut self, port: u16) -> Result<TcpStream> {
        timeout(DEADLINE, async {
            loop {
                self.check_children()?;
                match TcpStream::connect(("127.0.0.1", port)).await {
                    Ok(stream) => {
                        stream.set_nodelay(true)?;
                        // bell202 accepts once: this is the real connection, not a probe.
                        return Ok(stream);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                        sleep(Duration::from_millis(100)).await;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        })
        .await
        .context("waiting for interop TCP listener")?
    }

    fn bell202() -> Result<Modem> {
        let binary = std::env::var_os("BELL202_BIN")
            .filter(|binary| !binary.is_empty())
            .map(PathBuf::from)
            .context("BELL202_BIN must point to a built bell202 modem; run tests/run_direwolf_interop.sh to install and configure it")?;
        let help = Command::new(&binary).arg("--help").output()?;
        ensure!(help.status.success(), "bell202 --help failed");
        let help = String::from_utf8(help.stdout)?;
        // RX alone is insufficient: queued local audio also consumes T1.
        let busy = help.contains("--busy-threshold-db") && help.contains("--full-duplex");
        eprintln!(
            "Modem {}: {}",
            binary.display(),
            if busy {
                "RX/TX busy notifications, 3s timers, larger extended windows"
            } else {
                "legacy modem, conservative audio timers/windows"
            }
        );
        Ok(Modem { binary, busy })
    }
}

fn free_port() -> Result<u16> {
    Ok(TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port())
}

fn verify_capture(path: &Path, extended: bool, case: &str) -> Result<()> {
    let bytes = fs::read(path)?;
    ensure!(
        bytes.len() >= 24 && bytes[..4] == [0xd4, 0xc3, 0xb2, 0xa1],
        "invalid PCAP header"
    );
    ensure!(
        u32::from_le_bytes(bytes[20..24].try_into()?) == 3,
        "expected AX.25 PCAP"
    );
    let mut remaining = &bytes[24..];
    let mut controls = Vec::new();
    while !remaining.is_empty() {
        ensure!(remaining.len() >= 16, "truncated PCAP record header");
        let size = usize::try_from(u32::from_le_bytes(remaining[8..12].try_into()?))?;
        remaining = &remaining[16..];
        let frame = remaining.get(..size).context("truncated PCAP frame")?;
        ensure!(
            frame.len() >= 15 && frame[6] & 1 == 0 && frame[13] & 1 == 1,
            "expected direct AX.25 frame"
        );
        controls.push(frame[14] & !0x10); // Ignore poll/final in U frames.
        if frame[14] & !0x10 == 0xaf
            && let rax25::PacketType::Xid(xid) =
                rax25::Packet::parse(frame, Some(extended))?.packet_type()
            && let Some(functions) = xid.parameters.as_ref().and_then(|p| p.optional_functions)
        {
            let source = rax25::Addr::parse(&frame[7..14])?;
            eprintln!(
                "[{case}] XID from {}: PI=3 0x{functions:06x}, single-SREJ={}, multi-SREJ={}",
                source.callsign().call(),
                functions & 4 != 0,
                functions & 0x20_0000 != 0
            );
        }
        remaining = &remaining[size..];
    }
    let setup = if extended { 0x6f } else { 0x2f };
    ensure!(
        controls.iter().find(|control| **control != 0xaf) == Some(&setup),
        "expected SABM(E) for requested mode"
    );
    ensure!(
        !controls.contains(&(if extended { 0x2f } else { 0x6f })),
        "unexpected mode fallback"
    );
    ensure!(controls.last() == Some(&0x63), "expected final UA");
    if false {
        // We can't do this because sometimes delayed packets can squeeze in
        // after we've sent DISC but before receiving UA. It could be a REJ
        // because of a duplicate packet we sent, or Dire Wolf becoming bored
        // and triggering an RR probe.
        //
        // This should explain the question in commit
        // 5f5d9e10346cbbeafa3a63805c99b6cced858211.
        ensure!(
            controls.iter().rev().nth(1) == Some(&0x43),
            "expected DISC immediately before final UA"
        );
    }
    ensure!(
        controls[..controls.len() - 1].contains(&0x43),
        "expected DISC before final UA"
    );
    Ok(())
}

fn tshark_capture(path: &Path) -> String {
    let temp = std::env::temp_dir().join(format!(
        "rax25-tshark-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    ));
    if let Err(error) =
        fs::create_dir(&temp).and_then(|()| fs::copy(path, temp.join("capture.pcap")).map(|_| ()))
    {
        return format!("cannot stage {} for tshark: {error}", path.display());
    }
    let staged = temp.join("capture.pcap");
    let result = match Command::new("tshark").args(["-Vr"]).arg(&staged).output() {
        Ok(output) => format!(
            "tshark -r {} (exit {}):\n{}{}",
            path.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ),
        Err(error) => format!("tshark -r {} failed to run: {error}", path.display()),
    };
    let _ = fs::remove_dir_all(temp);
    result
}

async fn echo(agw: &mut AGWServer, log: &mut File, payloads: &[Vec<u8>]) -> Result<()> {
    use std::io::Write;
    let remote = Call::from_bytes(b"M0TST-1")?;
    let local = Call::from_bytes(b"M0TST-2")?;
    let packet = agw.recv().await?;
    writeln!(log, "{packet:?}")?;
    ensure!(
        matches!(packet, Packet::IncomingConnect { port: Port(1), ref src, ref dst, .. } if *src == remote && *dst == local),
        "expected incoming AX.25 connection, got {packet:?}"
    );
    for expected in payloads {
        let mut received = Vec::new();
        while received.len() < expected.len() {
            let packet = agw.recv().await?;
            writeln!(log, "{packet:?}")?;
            match packet {
                Packet::Data {
                    port: Port(1),
                    src,
                    dst,
                    data,
                    ..
                } if src == remote && dst == local => {
                    ensure!(!data.is_empty(), "empty AGW data");
                    received.extend_from_slice(&data);
                    agw.send(&Packet::Data {
                        port: Port(1),
                        pid: Pid(0xf0),
                        src: local.clone(),
                        dst: remote.clone(),
                        data,
                    })
                    .await?;
                }
                other => bail!("expected AGW data, got {other:?}"),
            }
        }
        ensure!(received == *expected, "AGW received corrupt or extra bytes");
    }
    let packet = agw.recv().await?;
    writeln!(log, "{packet:?}")?;
    ensure!(
        matches!(packet, Packet::Disconnect { port: Port(1), ref src, ref dst, .. } if *src == remote && *dst == local),
        "expected AGW disconnect, got {packet:?}"
    );
    Ok(())
}

fn recovery_summary(path: &Path, extended: bool) -> Result<()> {
    let capture = fs::read(path)?;
    let mut records = capture.get(24..).context("missing pcap header")?;
    let mut seen = std::collections::HashSet::new();
    let mut resends = 0;
    let mut rejects = 0;
    let mut selective_rejects = 0;
    while !records.is_empty() {
        ensure!(records.len() >= 16, "truncated pcap record");
        let size = usize::try_from(u32::from_le_bytes(records[8..12].try_into()?))?;
        let frame = records.get(16..16 + size).context("truncated pcap frame")?;
        let packet = rax25::Packet::parse(frame, Some(extended))?;
        match packet.packet_type() {
            rax25::PacketType::Iframe(data) => {
                if !seen.insert((frame[7..14].to_vec(), data.ns, data.payload.clone())) {
                    resends += 1;
                }
            }
            rax25::PacketType::Rej(_) => rejects += 1,
            rax25::PacketType::Srej(_) => selective_rejects += 1,
            _ => {}
        }
        records = &records[16 + size..];
    }
    eprintln!(
        "Dire Wolf file recovery: {resends} repeated I frames, {rejects} REJ, {selective_rejects} SREJ frames (extended={extended})"
    );
    ensure!(resends > 0, "file transfer exercised no retransmissions");
    if extended {
        ensure!(
            selective_rejects > 0,
            "file transfer exercised no SREJ recovery"
        );
        ensure!(rejects == 0, "SREJ file transfer unexpectedly used REJ");
    } else {
        ensure!(rejects > 0, "file transfer exercised no REJ recovery");
    }
    Ok(())
}

fn transfer_payloads(files: bool, dir: &Path) -> Result<Vec<Vec<u8>>> {
    let mut payloads = vec![
        b"rax25 to Dire Wolf over Bell 202 audio\r\n".to_vec(),
        (0..=255).collect(),
        vec![0xc0, 0xdb, 0, 0xff, 0xc0, 0xdb, 0x7e],
    ];
    if files {
        // Multiple transmit windows and modulo-8 sequence wraps. AGW
        // verifies the upload; rax25 verifies the echoed download.
        let file: Vec<_> = (0..4096_u32)
            .map(|n| n.wrapping_mul(73).wrapping_add(n >> 8).to_le_bytes()[0])
            .collect();
        fs::write(dir.join("transfer.bin"), &file)?;
        payloads.push(file);
        eprintln!("Dire Wolf file transfer: 4096-byte upload and echoed download");
    }
    Ok(payloads)
}

fn configure_bulk_audio(config: &Path, modem: &Modem) -> Result<()> {
    use std::io::Write;
    // Test setup, not protocol policy: without RX/TX busy indications a
    // 1200-baud full window requires a longer wall-clock retry allowance.
    writeln!(
        fs::OpenOptions::new().append(true).open(config)?,
        "FRACK {}\nEMAXFRAME {}\nMAXFRAME {}",
        if modem.busy { 3 } else { 15 },
        modem.window(true),
        if modem.busy { 7 } else { 4 },
    )?;
    Ok(())
}

fn check_echoed(expected: &[u8], received: &[u8], files: bool, dir: &Path) -> Result<()> {
    if files && expected.len() == 4096 {
        fs::write(dir.join("download-received.bin"), received)?;
    }
    ensure!(received == expected, "corrupt or extra echoed bytes");
    Ok(())
}

async fn connect_interop(
    stream: TcpStream,
    extended: bool,
    files: bool,
    dir: &Path,
    deadline: Duration,
    modem: &Modem,
) -> Result<rax25::r#async::Client> {
    let mut builder = ConnectionBuilder::new(Callsign::new("M0TST-1")?, PortType::Tcp(stream))?
        .extended(Some(extended))
        .srt_default(Duration::from_secs(modem.retry(files)))
        .mtu(256)
        .capture(dir.join("rax25.pcap"));
    if files && extended {
        // Dire Wolf ignores pre-connect XID and assumes selective recovery
        // after SABME. Explicitly negotiate it after establishment instead.
        builder = builder.srej(true).xid_after_connect(rax25::XidConfig {
            acknowledgement_timer: Duration::from_secs(if modem.busy { 3 } else { 15 }),
            management_timeout: Duration::from_secs(if modem.busy { 3 } else { 5 }),
            receive_window_extended: modem.window(true),
            ..Default::default()
        });
    }
    let client = timeout(deadline, builder.connect(Callsign::new("M0TST-2")?))
        .await
        .context("AX.25 connect timed out")??;
    if files && extended {
        let parameters = client
            .negotiated_parameters()
            .context("missing bulk XID agreement")?;
        ensure!(
            parameters.extended && parameters.reject_mode == rax25::RejectMode::MultiSrej,
            "unexpected bulk negotiation: {parameters:?}"
        );
        if modem.busy {
            ensure!(
                parameters.transmit_window == modem.window(true)
                    && parameters.receive_window == modem.window(true)
                    && parameters.acknowledgement_timer == Duration::from_secs(3),
                "busy-aware bulk settings were not negotiated: {parameters:?}"
            );
        }
        eprintln!("[direwolf_lossy_file_transfer_extended_srej] negotiated: {parameters:?}");
    }
    Ok(client)
}

async fn srej_interop(extended: bool, srej: Option<bool>) -> Result<()> {
    let bell202 = Harness::bell202()?;
    let (case, mut harness) = selective_harness(extended, srej)?;
    let result = Box::pin(async {
        let agw_port = free_port()?;
        let mut kiss_port = free_port()?;
        while kiss_port == agw_port { kiss_port = free_port()?; }
        let config = harness.dir.join("direwolf.conf");
        fs::write(&config, format!(
            "ADEVICE from-bell202 to-bell202\nARATE 48000\nACHANNELS 1\nCHANNEL 0\nMYCALL M0TST-2\nMODEM 1200\nAGWPORT {agw_port}\nKISSPORT 0\nTXDELAY 20\nTXTAIL 10\nPERSIST 255\nSLOTTIME 1\nFIX_BITS 0\n"
        ))?;
        if srej.is_some() {
            use std::io::Write as _;
            // Small packets and a four-frame window make two missing frames
            // observable without racing the real 1200-baud modem's timers.
            writeln!(File::options().append(true).open(&config)?,
                "PACLEN 32\nMAXFRAME 4\nEMAXFRAME {}\nFRACK {}", bell202.window(false), bell202.retry(false))?;
        }
        // Dire Wolf 1.7 truncates long -c arguments; keep the filename short
        // even when Tickbox's persistent target directory has a long path.
        let binary = std::env::var_os("DIREWOLF_BIN").unwrap_or_else(|| "/usr/bin/direwolf".into());
        let binary = PathBuf::from(binary);
        let binary = if binary.is_relative() && binary.components().count() > 1 {
            fs::canonicalize(binary)?
        } else {
            binary
        };
        harness.spawn("direwolf", Command::new(binary).current_dir(&harness.dir).arg("-c").arg("direwolf.conf").args(["-t", "0"]))?;
        let mut agw = AGWServer::new(harness.connect(agw_port).await?);
        agw.send(&Packet::RegisterCallsign(Port(1), Call::from_bytes(b"M0TST-2")?)).await?;
        let registered = timeout(DEADLINE, agw.recv()).await.context("AGW registration timed out")??;
        ensure!(matches!(registered, Packet::RegisterCallsignReply { success: true, .. }), "registration rejected: {registered:?}");
        harness.spawn("bell202", &mut bell202.command(kiss_port))?;
        let modem = harness.connect(kiss_port).await?;
        let proxy_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
        let stream = TcpStream::connect(proxy_listener.local_addr()?).await?;
        let (proxy_stream, _) = proxy_listener.accept().await?;
        let payloads = vec![
            (0..=255).collect::<Vec<u8>>(),
            b"rax25 to Dire Wolf over Bell 202 audio\r\n".to_vec(),
            vec![0xc0, 0xdb, 0, 0xff, 0xc0, 0xdb, 0x7e],
        ];
        let mut agw_log = File::create(harness.dir.join("agw.log"))?;
        let client = async {
            let mut builder = ConnectionBuilder::new(Callsign::new("M0TST-1")?, PortType::Tcp(stream))?
                .extended(Some(extended))
                .srt_default(Duration::from_secs(bell202.retry(false)))
                .mtu(if srej.is_some() { 32 } else { 256 })
                .capture(harness.dir.join("rax25.pcap"));
            if let Some(enabled) = srej {
                // Dire Wolf 1.7 ignores XID before SABM(E), unlike rax25's
                // original XID-first setup. Exercise the real connected MDL.
                builder = builder.srej(enabled).xid_after_connect(rax25::XidConfig {
                    acknowledgement_timer: Duration::from_secs(bell202.retry(false)),
                    management_timeout: Duration::from_secs(bell202.retry(false)),
                    receive_window_extended: bell202.window(false),
                    ..Default::default()
                });
            }
            let mut client = timeout(DEADLINE, builder.connect(Callsign::new("M0TST-2")?))
                .await.context("AX.25 connect timed out")??;
            if let Some(enabled) = srej {
                let negotiated = client.negotiated_parameters().context("no XID agreement")?;
                eprintln!("[{case}] negotiated: {negotiated:?}");
                ensure!(negotiated.reject_mode == if enabled { rax25::RejectMode::MultiSrej }
                    else { rax25::RejectMode::Rej }, "unexpected recovery: {negotiated:?}");
            }
            for expected in &payloads {
                // Larger go-back-N bursts can exceed 30 seconds of audio
                // during recovery, even with only 3 seconds of idle T1 time.
                let deadline = if bell202.busy { Duration::from_secs(90) } else { DEADLINE };
                timeout(deadline, async {
                    client.write(expected).await?.await?;
                    let mut received = Vec::new();
                    while received.len() < expected.len() {
                        let bytes = client.read().await?;
                        ensure!(!bytes.is_empty(), "unexpected AX.25 EOF");
                        received.extend(bytes);
                    }
                    ensure!(received == *expected, "corrupt or extra echoed bytes");
                    Ok::<_, anyhow::Error>(())
                }).await.context("AX.25 echo timed out")??;
            }
            timeout(DEADLINE, client.disconnect()).await.context("AX.25 disconnect timed out")??;
            Ok::<_, anyhow::Error>(())
        };
        let server = async {
            timeout(Duration::from_secs(180), echo(&mut agw, &mut agw_log, &payloads))
                .await.context("AGW echo/disconnect timed out")?
        };
        let exchange = async { tokio::try_join!(client, server)?; Ok::<_, anyhow::Error>(()) };
        tokio::select! {
            biased;
            result = exchange => result?,
            result = srej_loss::proxy(proxy_stream, modem, &harness.dir, extended, srej.is_some()) => {
                result?;
                bail!("KISS proxy ended before exchange completed");
            }
        }
        verify_capture(&harness.dir.join("rax25.pcap"), extended, &case)?;
        if let Some(enabled) = srej { srej_loss::verify(&harness.dir, extended, enabled)?; }
        harness.check_children()?;
        Ok::<_, anyhow::Error>(())
    }).await;
    report_case(&case, &harness, result)
}

#[tokio::test]
#[ignore = "requires audio dependencies; use tests/run_direwolf_interop.sh"]
async fn direwolf_standard_srej_audio() -> Result<()> {
    srej_interop(false, Some(true)).await
}

#[tokio::test]
#[ignore = "requires audio dependencies; use tests/run_direwolf_interop.sh"]
async fn direwolf_extended_srej_audio() -> Result<()> {
    srej_interop(true, Some(true)).await
}

#[tokio::test]
#[ignore = "requires audio dependencies; use tests/run_direwolf_interop.sh"]
async fn direwolf_standard_rej_audio() -> Result<()> {
    srej_interop(false, Some(false)).await
}

#[tokio::test]
#[ignore = "requires audio dependencies; use tests/run_direwolf_interop.sh"]
async fn direwolf_extended_rej_audio() -> Result<()> {
    srej_interop(true, Some(false)).await
}

async fn interop(extended: bool, drop_percent: u8, files: bool) -> Result<()> {
    let bell202 = Harness::bell202()?;
    let (case, mut harness) = random_harness(extended, drop_percent, files)?;
    let result = async {
        let agw_port = free_port()?;
        let mut kiss_port = free_port()?;
        while kiss_port == agw_port { kiss_port = free_port()?; }
        let config = harness.dir.join("direwolf.conf");
        fs::write(&config, format!(
            "ADEVICE from-bell202 to-bell202\nARATE 48000\nACHANNELS 1\nCHANNEL 0\nMYCALL M0TST-2\nMODEM 1200\nAGWPORT {agw_port}\nKISSPORT 0\nTXDELAY 20\nTXTAIL 10\nPERSIST 255\nSLOTTIME 1\nFIX_BITS 0\n"
        ))?;
        if files {
            configure_bulk_audio(&config, &bell202)?;
        }
        // Dire Wolf 1.7 truncates long -c arguments; keep the filename short
        // even when Tickbox's persistent target directory has a long path.
        let binary = std::env::var_os("DIREWOLF_BIN").unwrap_or_else(|| "/usr/bin/direwolf".into());
        let binary = PathBuf::from(binary);
        let binary = if binary.is_relative() && binary.components().count() > 1 {
            fs::canonicalize(binary)?
        } else {
            binary
        };
        harness.spawn("direwolf", Command::new(binary).current_dir(&harness.dir).arg("-c").arg("direwolf.conf").args(["-t", "0"]))?;
        let mut agw = AGWServer::new(harness.connect(agw_port).await?);
        agw.send(&Packet::RegisterCallsign(Port(1), Call::from_bytes(b"M0TST-2")?)).await?;
        let registered = timeout(DEADLINE, agw.recv()).await.context("AGW registration timed out")??;
        ensure!(matches!(registered, Packet::RegisterCallsignReply { success: true, .. }), "registration rejected: {registered:?}");
        harness.spawn("bell202", &mut bell202.command(kiss_port))?;
        let proxy_port = loop {
            let port = free_port()?;
            if port != agw_port && port != kiss_port { break port; }
        };
        let root = manifest_dir()?;
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map_or_else(|| root.join("target"), |path| root.join(path));
        let proxy = std::env::var_os("KISS_LOSS_PROXY_BIN")
            .map_or_else(|| target.join("debug/examples/kiss_loss_proxy"), PathBuf::from);
        harness.spawn("loss-proxy", Command::new(proxy).args([
            "--listen", &format!("127.0.0.1:{proxy_port}"),
            "--modem", &format!("tcp://127.0.0.1:{kiss_port}"),
            "--tx-drop", &drop_percent.to_string(),
            "--rx-drop", &drop_percent.to_string(),
            "--seed", "123",
            "--capture",
        ]).arg(harness.dir.join("loss.pcapng")))?;
        let stream = harness.connect(proxy_port).await?;
        let deadline = if files { Duration::from_secs(600) } else if drop_percent == 0 { DEADLINE } else { Duration::from_secs(180) };
        let payloads = transfer_payloads(files, &harness.dir)?;
        let mut agw_log = File::create(harness.dir.join("agw.log"))?;
        let client = async {
            let mut client = connect_interop(stream, extended, files, &harness.dir, deadline, &bell202).await?;
            for expected in &payloads {
                timeout(deadline, async {
                    client.write(expected).await?.await?;
                    let mut received = Vec::new();
                    while received.len() < expected.len() {
                        let bytes = client.read().await?;
                        ensure!(!bytes.is_empty(), "unexpected AX.25 EOF");
                        received.extend(bytes);
                    }
                    check_echoed(expected, &received, files, &harness.dir)?;
                    Ok::<_, anyhow::Error>(())
                }).await.context("AX.25 echo timed out")??;
            }
            timeout(deadline, client.disconnect()).await.context("AX.25 disconnect timed out")??;
            Ok::<_, anyhow::Error>(())
        };
        let server = async {
            timeout(Duration::from_mins(15), echo(&mut agw, &mut agw_log, &payloads))
                .await.context("AGW echo/disconnect timed out")?
        };
        tokio::try_join!(client, server)?;
        let capture = harness.dir.join("rax25.pcap");
        if let Err(error) = verify_capture(&capture, extended, case) {
            bail!("{error}\n{}", tshark_capture(&capture));
        }
        if files {
            recovery_summary(&capture, extended)?;
        }
        harness.check_children()?;
        Ok::<_, anyhow::Error>(())
    }.await;
    if result.is_err() {
        eprintln!("{}", tshark_capture(&harness.dir.join("loss.pcapng")));
    }
    report_case(case, &harness, result)
}

#[tokio::test]
#[ignore = "requires Dire Wolf, bell202, ALSA Pulse plugin and live Pulse audio; use tests/run_direwolf_interop.sh"]
async fn direwolf_standard_audio() -> Result<()> {
    for percent in [0, 5, 10] {
        interop(false, percent, false).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "slow bulk-transfer stress test; run tests/run_direwolf_interop.sh direwolf_lossy_file_transfer manually"]
async fn direwolf_lossy_file_transfer() -> Result<()> {
    // Exercise bulk REJ recovery here; the dedicated SREJ tests separately
    // negotiate and verify selective recovery in both numbering modes.
    interop(false, 10, true).await
}

#[tokio::test]
#[ignore = "slow bulk-transfer stress test; run tests/run_direwolf_interop.sh direwolf_lossy_file_transfer_extended_srej manually"]
async fn direwolf_lossy_file_transfer_extended_srej() -> Result<()> {
    interop(true, 10, true).await
}

#[tokio::test]
#[ignore = "requires Dire Wolf, bell202, ALSA Pulse plugin and live Pulse audio; use tests/run_direwolf_interop.sh"]
async fn direwolf_extended_audio() -> Result<()> {
    for percent in [0, 5, 10] {
        interop(true, percent, false).await?;
    }
    Ok(())
}
