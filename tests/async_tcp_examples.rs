//! Check that async server and client can talk to each other, in the no-error
//! case.
//!
//! This whole thing was AI-coded. It looks right, and I fixed a thing or two,
//! but being a test I have not super validated it.
use std::collections::HashSet;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use rand::{rngs::StdRng, Rng, RngExt, SeedableRng};

const TIMEOUT: Duration = Duration::from_secs(10);

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn async_examples_echo_over_tcp_and_exit_on_client_eof() -> TestResult {
    run_async_examples_echo_test(TestCase {
        name: "standard",
        client_extra_args: &[],
        server_extra_args: &[],
        bridge_mode: BridgeMode::Reliable,
        timeout: TIMEOUT,
        expected_capture: Some(EXPECTED_CAPTURE),
        preserve_captures_on_failure: false,
    })
}

#[test]
fn async_examples_echo_over_tcp_with_extended_client() -> TestResult {
    run_async_examples_echo_test(TestCase {
        name: "extended-client",
        client_extra_args: &["-e"],
        server_extra_args: &[],
        bridge_mode: BridgeMode::Reliable,
        timeout: TIMEOUT,
        expected_capture: Some(EXPECTED_EXTENDED_CAPTURE),
        preserve_captures_on_failure: false,
    })
}

#[test]
fn async_examples_echo_over_lossy_tcp() -> TestResult {
    for seeds in [
        (0, 0),
        (0x44, 0),
        // This seed triggers what I consider to be a bug in the spec: No
        // retransmission of data on lost UA.
        // (0,0x44),
        (123, 321),
    ] {
        println!("Testing seed {seeds:?}");
        run_async_examples_echo_test(TestCase {
            name: "lossy",
            client_extra_args: &["--srt", "100ms", "--t3v", "200ms"],
            server_extra_args: &["--srt", "100ms", "--t3v", "200ms"],
            bridge_mode: BridgeMode::Lossy {
                data_only: false,
                drop_probability_percent: 50,
                client_to_server_seed: seeds.0,
                server_to_client_seed: seeds.1,
            },
            timeout: Duration::from_secs(5),
            expected_capture: None,
            preserve_captures_on_failure: true,
        })?;
    }
    Ok(())
}

/// This test works the retransmissions and resync harder. It doesn't drop any
/// SABM/UA/DM, but goes really hard on I and RR frames.
///
/// Disabled for now since these are flaky.
#[test]
#[ignore = "flaky: often fails"]
fn async_examples_echo_over_lossy_tcp_only_data() -> TestResult {
    let args = &[
        "--srt",
        "100ms",
        "--t3v",
        "200ms",
        "--experiments",
        "reset-retry-on-iframe-ack,resend-on-rr-command",
    ];
    for seeds in [(0, 0), (0x44, 0), (0, 0x44), (123, 321)] {
        println!("Testing seed {seeds:?}");
        run_async_examples_echo_test(TestCase {
            name: "lossy-data",
            client_extra_args: args,
            server_extra_args: args,
            bridge_mode: BridgeMode::Lossy {
                data_only: true,
                drop_probability_percent: 75,
                client_to_server_seed: seeds.0,
                server_to_client_seed: seeds.1,
            },
            timeout: Duration::from_secs(5),
            expected_capture: None,
            preserve_captures_on_failure: true,
        })?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct TestCase {
    name: &'static str,
    client_extra_args: &'static [&'static str],
    server_extra_args: &'static [&'static str],
    bridge_mode: BridgeMode,
    timeout: Duration,
    expected_capture: Option<&'static [&'static str]>,
    preserve_captures_on_failure: bool,
}

#[derive(Clone, Copy)]
enum BridgeMode {
    Reliable,
    Lossy {
        data_only: bool,
        drop_probability_percent: u8,
        client_to_server_seed: u64,
        server_to_client_seed: u64,
    },
}

fn run_async_examples_echo_test(test_case: TestCase) -> TestResult {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    build_examples(&manifest_dir)?;

    let bridge = start_kiss_bridge(test_case.bridge_mode)?;
    let server_endpoint = format!("tcp://{}", bridge.server_addr);
    let client_endpoint = format!("tcp://{}", bridge.client_addr);

    let server_exe = example_exe(&manifest_dir, "async_server");
    let client_exe = example_exe(&manifest_dir, "async_client");
    let captures = TestDir::new(&format!("rax25-async-captures-{}", test_case.name))?;
    let client_capture = captures.path.join("client.pcap");
    let server_capture = captures.path.join("server.pcap");

    let result = (|| -> TestResult {
        let mut server = ChildGuard::new(
            Command::new(&server_exe)
                .args(["-p", &server_endpoint, "-s", "M0TST-2", "--capture"])
                .arg(&server_capture)
                .args(test_case.server_extra_args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| io::Error::other(format!("spawning {}: {e}", server_exe.display())))?,
        );

        let mut client_command = Command::new(&client_exe);
        client_command
            .args(["-p", &client_endpoint, "-s", "M0TST-1"])
            .args(test_case.client_extra_args)
            .arg("--capture")
            .arg(&client_capture)
            .arg("M0TST-2")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut client =
            ChildGuard::new(client_command.spawn().map_err(|e| {
                io::Error::other(format!("spawning {}: {e}", client_exe.display()))
            })?);

        let mut client_stdin = client
            .child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("client stdin was not piped"))?;
        let client_stdout = client
            .child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("client stdout was not piped"))?;
        let (client_lines, stdout_reader) = spawn_line_reader(client_stdout);
        let mut seen_stdout = Vec::new();

        recv_line_equal(
            &client_lines,
            &mut seen_stdout,
            "Welcome to the server!",
            test_case.timeout,
        )?;

        // These messages are of ascending length so that it's easier to read
        // packet traces.
        for msg in ["alpha", "bravoo", "charliee"] {
            client_stdin.write_all(msg.as_bytes())?;
            client_stdin.flush()?;
            recv_line_equal(
                &client_lines,
                &mut seen_stdout,
                &format!("Got <{msg}>"),
                test_case.timeout,
            )?;
        }

        drop(client_stdin);
        wait_for_success("async_client", &mut client, test_case.timeout)?;
        wait_for_success("async_server", &mut server, test_case.timeout)?;

        stdout_reader
            .join()
            .map_err(|_| io::Error::other("client stdout reader panicked"))?;
        bridge
            .done
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| io::Error::other("KISS bridge did not stop"))?
            .map_err(io::Error::other)?;

        let client_capture_text = tshark_text(&client_capture)?;
        let server_capture_text = tshark_text(&server_capture)?;
        if let Some(expected) = test_case.expected_capture {
            assert_tshark_lines("client capture", &client_capture_text, expected);
        }
        if let Some(expected) = test_case.expected_capture {
            assert_tshark_lines("server capture", &server_capture_text, expected);
        }

        Ok(())
    })();

    if let Err(e) = result {
        if test_case.preserve_captures_on_failure {
            let saved = captures.copy_to_failure_dir(&manifest_dir, test_case.name)?;
            return Err(io::Error::other(format!(
                "{e}\nSaved capture files for manual inspection in {}",
                saved.display()
            ))
            .into());
        }
        return Err(e);
    }

    Ok(())
}

const EXPECTED_CAPTURE: &[&str] = &[
    "1|9a:60:a8:a6:a8:40:63|9a:60:a8:a6:a8:40:e4|0x3f|||U P, func=SABM",
    "2|9a:60:a8:a6:a8:40:e5|9a:60:a8:a6:a8:40:62|0x73|||U F, func=UA",
    "3|9a:60:a8:a6:a8:40:65|9a:60:a8:a6:a8:40:e2|0x00|0xf0|57656c636f6d6520746f2074686520736572766572210a|Text",
    "4|9a:60:a8:a6:a8:40:63|9a:60:a8:a6:a8:40:e4|0x20|0xf0|616c706861|Text",
    "5|9a:60:a8:a6:a8:40:65|9a:60:a8:a6:a8:40:e2|0x22|0xf0|476f74203c616c7068613e0a|Text",
    "6|9a:60:a8:a6:a8:40:63|9a:60:a8:a6:a8:40:e4|0x42|0xf0|627261766f6f|Text",
    "7|9a:60:a8:a6:a8:40:65|9a:60:a8:a6:a8:40:e2|0x44|0xf0|476f74203c627261766f6f3e0a|Text",
    "8|9a:60:a8:a6:a8:40:63|9a:60:a8:a6:a8:40:e4|0x64|0xf0|636861726c696565|Text",
    "9|9a:60:a8:a6:a8:40:65|9a:60:a8:a6:a8:40:e2|0x66|0xf0|476f74203c636861726c6965653e0a|Text",
    "10|9a:60:a8:a6:a8:40:63|9a:60:a8:a6:a8:40:e4|0x53|||U P, func=DISC",
    "11|9a:60:a8:a6:a8:40:e5|9a:60:a8:a6:a8:40:62|0x73|||U F, func=UA",
];

const EXPECTED_EXTENDED_CAPTURE: &[&str] = &[
    "1|9a:60:a8:a6:a8:40:63|9a:60:a8:a6:a8:40:e4|0x7f|||U P, func=SABME",
    "2|9a:60:a8:a6:a8:40:e5|9a:60:a8:a6:a8:40:62|0x73|||U F, func=UA",
    "3|9a:60:a8:a6:a8:40:65|9a:60:a8:a6:a8:40:e2|0x00|0x00|f057656c636f6d6520746f2074686520736572766572210a|I, N(R)=0, N(S)=0, Unknown (0x00)",
    "4|9a:60:a8:a6:a8:40:63|9a:60:a8:a6:a8:40:e4|0x00|0x02|f0616c706861|I, N(R)=0, N(S)=0, Unknown (0x02)",
    "5|9a:60:a8:a6:a8:40:65|9a:60:a8:a6:a8:40:e2|0x02|0x02|f0476f74203c616c7068613e0a|I, N(R)=0, N(S)=1, Unknown (0x02)",
    "6|9a:60:a8:a6:a8:40:63|9a:60:a8:a6:a8:40:e4|0x02|0x04|f0627261766f6f|I, N(R)=0, N(S)=1, Unknown (0x04)",
    "7|9a:60:a8:a6:a8:40:65|9a:60:a8:a6:a8:40:e2|0x04|0x04|f0476f74203c627261766f6f3e0a|I, N(R)=0, N(S)=2, Unknown (0x04)",
    "8|9a:60:a8:a6:a8:40:63|9a:60:a8:a6:a8:40:e4|0x04|0x06|f0636861726c696565|I, N(R)=0, N(S)=2, RFC1144 (compressed)",
    "9|9a:60:a8:a6:a8:40:65|9a:60:a8:a6:a8:40:e2|0x06|0x06|f0476f74203c636861726c6965653e0a|I, N(R)=0, N(S)=3, RFC1144 (compressed)",
    "10|9a:60:a8:a6:a8:40:63|9a:60:a8:a6:a8:40:e4|0x53|||U P, func=DISC",
    "11|9a:60:a8:a6:a8:40:e5|9a:60:a8:a6:a8:40:62|0x73|||U F, func=UA",
];

fn build_examples(manifest_dir: &Path) -> TestResult {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .current_dir(manifest_dir)
        .args([
            "build",
            "--quiet",
            "--example",
            "async_client",
            "--example",
            "async_server",
        ])
        .status()
        .map_err(|e| io::Error::other(format!("running cargo build for examples: {e}")))?;
    if !status.success() {
        return Err(
            io::Error::other(format!("building async examples failed with {status}")).into(),
        );
    }
    Ok(())
}

fn example_exe(manifest_dir: &Path, name: &str) -> PathBuf {
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| manifest_dir.join("target"), PathBuf::from);
    let target_dir = if target_dir.is_absolute() {
        target_dir
    } else {
        manifest_dir.join(target_dir)
    };
    target_dir
        .join("debug")
        .join("examples")
        .join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(name: &str) -> TestResult<Self> {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)?
                .as_nanos()
        ));
        fs::create_dir(&path)?;
        Ok(Self { path })
    }

    fn copy_to_failure_dir(&self, manifest_dir: &Path, test_name: &str) -> TestResult<PathBuf> {
        let dir_name = self.path.file_name().ok_or_else(|| {
            io::Error::other(format!(
                "capture directory has no final path component: {}",
                self.path.display()
            ))
        })?;
        let dest = manifest_dir
            .join("target")
            .join("async_tcp_example_captures")
            .join(test_name)
            .join(dir_name);
        copy_dir_all(&self.path, &dest)?;
        Ok(dest)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn copy_dir_all(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst_path)?;
        } else {
            fs::copy(entry.path(), dst_path)?;
        }
    }
    Ok(())
}

fn tshark_text(path: &Path) -> TestResult<String> {
    let output = Command::new("tshark")
        .args([
            "-r",
            path.to_str().ok_or_else(|| {
                io::Error::other(format!("non-UTF-8 pcap path: {}", path.display()))
            })?,
            "-T",
            "fields",
            "-E",
            "separator=|",
            "-e",
            "frame.number",
            "-e",
            "ax25.src",
            "-e",
            "ax25.dst",
            "-e",
            "ax25.ctl",
            "-e",
            "ax25.pid",
            "-e",
            "data.data",
            "-e",
            "_ws.col.Info",
        ])
        .output()
        .map_err(|e| io::Error::other(format!("running tshark for {}: {e}", path.display())))?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "tshark failed for {} with {}; stderr:\n{}",
            path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn assert_tshark_lines(name: &str, actual: &str, expected: &[&str]) {
    let actual: Vec<_> = actual.lines().collect();
    assert!(
        actual == expected,
        "{name} did not match expected tshark output\n{}",
        unified_diff(name, expected, &actual)
    );
}

fn unified_diff(name: &str, expected: &[&str], actual: &[&str]) -> String {
    let mut diff = format!("--- {name} expected\n+++ {name} actual\n");
    let max_len = expected.len().max(actual.len());
    for i in 0..max_len {
        match (expected.get(i), actual.get(i)) {
            (Some(&expected), Some(&actual)) if expected == actual => {
                let _ = writeln!(diff, " {expected}");
            }
            (Some(&expected), Some(&actual)) => {
                let _ = writeln!(diff, "-{expected}");
                let _ = writeln!(diff, "+{actual}");
            }
            (Some(&expected), None) => {
                let _ = writeln!(diff, "-{expected}");
            }
            (None, Some(&actual)) => {
                let _ = writeln!(diff, "+{actual}");
            }
            (None, None) => {}
        }
    }
    diff
}

struct KissBridge {
    client_addr: std::net::SocketAddr,
    server_addr: std::net::SocketAddr,
    done: mpsc::Receiver<Result<(), String>>,
}

fn start_kiss_bridge(mode: BridgeMode) -> TestResult<KissBridge> {
    let client_listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| io::Error::other(format!("binding client KISS listener: {e}")))?;
    let server_listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| io::Error::other(format!("binding server KISS listener: {e}")))?;
    let client_addr = client_listener.local_addr()?;
    let server_addr = server_listener.local_addr()?;
    let (done_tx, done) = mpsc::channel();

    thread::spawn(move || {
        let result =
            run_kiss_bridge(client_listener, server_listener, mode).map_err(|e| e.to_string());
        let _ = done_tx.send(result);
    });

    Ok(KissBridge {
        client_addr,
        server_addr,
        done,
    })
}

#[allow(clippy::needless_pass_by_value)]
fn run_kiss_bridge(
    client_listener: TcpListener,
    server_listener: TcpListener,
    mode: BridgeMode,
) -> io::Result<()> {
    let (client, _) = client_listener.accept()?;
    let (server, _) = server_listener.accept()?;
    client.set_nodelay(true)?;
    server.set_nodelay(true)?;

    let client_read = client.try_clone()?;
    let server_read = server.try_clone()?;

    let (client_to_server_loss, server_to_client_loss) = match mode {
        BridgeMode::Reliable => (None, None),
        BridgeMode::Lossy {
            data_only,
            drop_probability_percent,
            client_to_server_seed,
            server_to_client_seed,
        } => (
            Some(LossConfig {
                data_only,
                drop_probability_percent,
                seed: client_to_server_seed,
            }),
            Some(LossConfig {
                data_only,
                drop_probability_percent,
                seed: server_to_client_seed,
            }),
        ),
    };

    let to_server =
        thread::spawn(move || copy_kiss_until_eof(client_read, server, client_to_server_loss));
    let to_client =
        thread::spawn(move || copy_kiss_until_eof(server_read, client, server_to_client_loss));

    to_server
        .join()
        .map_err(|_| io::Error::other("client-to-server bridge panicked"))??;
    to_client
        .join()
        .map_err(|_| io::Error::other("server-to-client bridge panicked"))??;
    Ok(())
}

#[derive(Clone, Copy)]
struct LossConfig {
    data_only: bool,
    drop_probability_percent: u8,
    seed: u64,
}

fn copy_kiss_until_eof(
    mut src: TcpStream,
    mut dst: TcpStream,
    loss: Option<LossConfig>,
) -> io::Result<()> {
    match loss {
        Some(loss) => copy_kiss_frames_with_loss(&mut src, &mut dst, loss)?,
        None => {
            io::copy(&mut src, &mut dst)?;
        }
    }
    dst.shutdown(Shutdown::Write)
}

fn copy_kiss_frames_with_loss(
    src: &mut TcpStream,
    dst: &mut TcpStream,
    loss: LossConfig,
) -> io::Result<()> {
    const KISS_FEND: u8 = 0xC0;

    let mut rng = StdRng::seed_from_u64(loss.seed);
    let mut seen_frames = HashSet::new();
    let mut frame = Vec::new();
    let mut in_frame = false;
    let mut buf = [0; 1024];
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            if !frame.is_empty()
                && !should_drop(
                    &mut rng,
                    loss.drop_probability_percent,
                    &mut seen_frames,
                    loss.data_only,
                    &frame,
                )
            {
                dst.write_all(&frame)?;
            }
            return Ok(());
        }

        for &byte in &buf[..n] {
            if byte == KISS_FEND {
                if in_frame {
                    frame.push(byte);
                    if !should_drop(
                        &mut rng,
                        loss.drop_probability_percent,
                        &mut seen_frames,
                        loss.data_only,
                        &frame,
                    ) {
                        dst.write_all(&frame)?;
                    }
                    frame.clear();
                    in_frame = false;
                } else {
                    frame.clear();
                    frame.push(byte);
                    in_frame = true;
                }
            } else if in_frame {
                frame.push(byte);
            } else {
                dst.write_all(&[byte])?;
            }
        }
    }
}

fn should_drop(
    rng: &mut impl Rng,
    drop_probability_percent: u8,
    seen_frames: &mut HashSet<Vec<u8>>,
    data_only: bool,
    frame: &[u8],
) -> bool {
    #[allow(clippy::collapsible_if)]
    if false {
        if !seen_frames.insert(frame.to_vec()) {
            return false;
        }
    }
    if data_only {
        use rax25::PacketType;
        const KISS_FEND: u8 = 0xC0;
        let [KISS_FEND, _kiss_command, payload @ .., KISS_FEND] = frame else {
            panic!()
        };
        let frame = rax25::unescape(payload);
        let packet = rax25::Packet::parse(&frame, None).unwrap();
        match packet.packet_type() {
            PacketType::Sabm(_)
            | PacketType::Sabme(_)
            | PacketType::Ua(_)
            | PacketType::Disc(_)
            | PacketType::Xid(_)
            | PacketType::Frmr(_)
            | PacketType::Dm(_) => return false,
            PacketType::Rr(_)
            | PacketType::Rnr(_)
            | PacketType::Ui(_)
            | PacketType::Test(_)
            | PacketType::Rej(_)
            | PacketType::Iframe(_)
            | PacketType::Srej(_) => {}
        }
    }

    // Here's room to put some extra rules about which packets to drop, if
    // needed.
    rng.random_range(0_u8..100) < drop_probability_percent
}

fn spawn_line_reader<R: Read + Send + 'static>(
    reader: R,
) -> (mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    (rx, handle)
}

fn recv_line_equal(
    rx: &mpsc::Receiver<String>,
    seen: &mut Vec<String>,
    expected: &str,
    timeout: Duration,
) -> TestResult {
    let deadline = Instant::now() + timeout;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::other(format!(
            "timed out waiting for client stdout matching {expected:?}; saw {seen:?}"
        ))
        .into());
    }
    match rx.recv_timeout(remaining) {
        Ok(line) => {
            let found = line == expected;
            seen.push(line.clone());
            if found {
                return Ok(());
            }
            Err(io::Error::other(format!(
                "client stdout line {line:?} did not match {expected:?}; saw {seen:?}"
            ))
            .into())
        }
        Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::other(format!(
            "timed out waiting for client stdout matching {expected:?}; saw {seen:?}"
        ))
        .into()),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::other(format!(
            "client stdout closed before {expected:?}; saw {seen:?}"
        ))
        .into()),
    }
}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn wait_for_success(name: &str, guard: &mut ChildGuard, timeout: Duration) -> TestResult {
    let status = wait_for_exit(&mut guard.child, timeout)?.ok_or_else(|| {
        io::Error::other(format!("{name} did not exit within {}s", timeout.as_secs()))
    })?;
    if status.success() {
        return Ok(());
    }

    let stderr = read_child_stderr(&mut guard.child);
    Err(io::Error::other(format!("{name} exited with {status}; stderr:\n{stderr}")).into())
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> io::Result<Option<ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn read_child_stderr(child: &mut Child) -> String {
    let Some(mut stderr) = child.stderr.take() else {
        return String::new();
    };
    let mut output = String::new();
    let _ = stderr.read_to_string(&mut output);
    output
}
