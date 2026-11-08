//! Opt-in, real Bell 202 audio interop with the installed Dire Wolf binary.
//! Run with `tests/run_direwolf_interop.sh`, or provide a live Pulse server.
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

impl Harness {
    fn new(extended: bool) -> Result<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let id = format!("{}_{}_{}", std::process::id(), nonce, extended);
        let root = manifest_dir()?;
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map_or_else(|| root.join("target"), |path| root.join(path));
        let dir = target.join("direwolf_interop").join(&id);
        fs::create_dir_all(&dir)?;
        eprintln!("Dire Wolf interop artifacts: {}", dir.display());
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

    fn bell202(&self) -> Result<PathBuf> {
        if let Some(binary) = std::env::var_os("BELL202_BIN") {
            return Ok(binary.into());
        }
        let root = manifest_dir()?;
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map_or_else(|| root.join("target"), |path| root.join(path))
            .join("direwolf_interop/rustradio-0.20.2");
        let log = File::create(self.dir.join("bell202-build.log"))?;
        let status = Command::new("cargo")
            .args([
                "install",
                "rustradio",
                "--version",
                "=0.20.2",
                "--registry",
                "crates-io",
                "--locked",
                "--example",
                "bell202",
                "--features",
                "audio",
            ])
            .arg("--root")
            .arg(&target)
            .arg("--target-dir")
            .arg(target.join("build"))
            .stdout(log.try_clone()?)
            .stderr(log)
            .status()
            .context("installing rustradio 0.20.2 bell202; alternatively set BELL202_BIN")?;
        ensure!(
            status.success(),
            "bell202 build failed; inspect bell202-build.log"
        );
        Ok(target.join("bin/bell202"))
    }
}

fn free_port() -> Result<u16> {
    Ok(TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port())
}

fn verify_capture(path: &Path, extended: bool) -> Result<()> {
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
        remaining = &remaining[size..];
    }
    let setup = if extended { 0x6f } else { 0x2f };
    ensure!(
        controls.first() == Some(&setup),
        "expected SABM(E) for requested mode"
    );
    ensure!(
        !controls.contains(&(if extended { 0x2f } else { 0x6f })),
        "unexpected mode fallback"
    );
    ensure!(controls.last() == Some(&0x63), "expected final UA");
    ensure!(
        controls.iter().rev().nth(1) == Some(&0x43),
        "expected DISC before final UA"
    );
    Ok(())
}

async fn echo(agw: &mut AGWServer, log: &mut File, payloads: &[Vec<u8>]) -> Result<()> {
    use std::io::Write;
    let remote = Call::from_bytes(b"M0TST-1")?;
    let local = Call::from_bytes(b"M0TST-2")?;
    let packet = agw.recv().await?;
    writeln!(log, "{packet:?}")?;
    ensure!(
        matches!(packet, Packet::IncomingConnect { port: Port(0), ref src, ref dst, .. } if *src == remote && *dst == local),
        "expected incoming AX.25 connection, got {packet:?}"
    );
    for expected in payloads {
        let mut received = Vec::new();
        while received.len() < expected.len() {
            let packet = agw.recv().await?;
            writeln!(log, "{packet:?}")?;
            match packet {
                Packet::Data {
                    port: Port(0),
                    src,
                    dst,
                    data,
                    ..
                } if src == remote && dst == local => {
                    ensure!(!data.is_empty(), "empty AGW data");
                    received.extend_from_slice(&data);
                    agw.send(&Packet::Data {
                        port: Port(0),
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
        matches!(packet, Packet::Disconnect { port: Port(0), ref src, ref dst, .. } if *src == remote && *dst == local),
        "expected AGW disconnect, got {packet:?}"
    );
    Ok(())
}

async fn interop(extended: bool) -> Result<()> {
    let mut harness = Harness::new(extended)?;
    let result = async {
        let bell202 = harness.bell202()?;
        let agw_port = free_port()?;
        let mut kiss_port = free_port()?;
        while kiss_port == agw_port { kiss_port = free_port()?; }
        let config = harness.dir.join("direwolf.conf");
        fs::write(&config, format!(
            "ADEVICE from-bell202 to-bell202\nARATE 48000\nACHANNELS 1\nCHANNEL 0\nMYCALL M0TST-2\nMODEM 1200\nAGWPORT {agw_port}\nKISSPORT 0\nTXDELAY 20\nTXTAIL 10\nPERSIST 255\nSLOTTIME 1\nFIX_BITS 0\n"
        ))?;
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
        agw.send(&Packet::RegisterCallsign(Port(0), Call::from_bytes(b"M0TST-2")?)).await?;
        let registered = timeout(DEADLINE, agw.recv()).await.context("AGW registration timed out")??;
        ensure!(matches!(registered, Packet::RegisterCallsignReply { success: true, .. }), "registration rejected: {registered:?}");
        harness.spawn("bell202", Command::new(bell202).args([
            "--audio", "--audio-input", "from-direwolf", "--audio-output", "to-direwolf",
            "--audio-rate", "48000", "--tcp-listen", &format!("127.0.0.1:{kiss_port}"),
        ]))?;
        let stream = harness.connect(kiss_port).await?;
        let payloads = vec![
            b"rax25 to Dire Wolf over Bell 202 audio\r\n".to_vec(),
            (0..=255).collect::<Vec<u8>>(),
            vec![0xc0, 0xdb, 0, 0xff, 0xc0, 0xdb, 0x7e],
        ];
        let mut agw_log = File::create(harness.dir.join("agw.log"))?;
        let client = async {
            let mut client = timeout(DEADLINE, ConnectionBuilder::new(Callsign::new("M0TST-1")?, PortType::Tcp(stream))?
                .extended(Some(extended))
                .srt_default(Duration::from_secs(5))
                .mtu(256)
                .capture(harness.dir.join("rax25.pcap"))
                .connect(Callsign::new("M0TST-2")?))
                .await.context("AX.25 connect timed out")??;
            for expected in &payloads {
                timeout(DEADLINE, async {
                    client.write(expected).await?;
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
        tokio::try_join!(client, server)?;
        verify_capture(&harness.dir.join("rax25.pcap"), extended)?;
        harness.check_children()?;
        Ok::<_, anyhow::Error>(())
    }.await;
    result.with_context(|| format!("interop artifacts: {}", harness.dir.display()))
}

#[tokio::test]
#[ignore = "requires Dire Wolf, bell202, ALSA Pulse plugin and live Pulse audio; use tests/run_direwolf_interop.sh"]
async fn direwolf_standard_audio() -> Result<()> {
    interop(false).await
}

#[tokio::test]
#[ignore = "requires Dire Wolf, bell202, ALSA Pulse plugin and live Pulse audio; use tests/run_direwolf_interop.sh"]
async fn direwolf_extended_audio() -> Result<()> {
    interop(true).await
}
