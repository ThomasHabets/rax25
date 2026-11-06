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

use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

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
fn async_examples_xid_echo_and_eof() -> TestResult {
    for (name, mode) in [
        ("xid-auto", None),
        ("xid-extended", Some("-e")),
        ("xid-standard", Some("--no-extended")),
    ] {
        let args = match mode {
            None => &["--xid"][..],
            Some("-e") => &["--xid", "-e"][..],
            _ => &["--xid", "--no-extended"][..],
        };
        run_xid_test(name, args, BridgeMode::Reliable)?;
    }
    Ok(())
}

#[test]
fn async_examples_xid_retransmits_lost_command_and_response() -> TestResult {
    for fault in [XidFault::DropCommand, XidFault::DropResponse] {
        run_xid_test(
            "xid-retry",
            &["--xid", "--srt", "100ms"],
            BridgeMode::Xid(fault),
        )?;
    }
    Ok(())
}

#[test]
fn async_examples_xid_legacy_fallback_is_standard_even_with_extended() -> TestResult {
    for fault in [XidFault::Dm, XidFault::Frmr, XidFault::Ignore] {
        for args in [
            &["--xid", "--srt", "50ms"][..],
            &["--xid", "-e", "--srt", "50ms"][..],
        ] {
            run_xid_test("xid-legacy", args, BridgeMode::Xid(fault))?;
        }
    }
    Ok(())
}

#[test]
fn async_examples_xid_splits_frames_to_peer_receive_limit() -> TestResult {
    run_xid_test(
        "xid-receive-limit",
        &["--xid", "--xid-receive-size", "8"],
        BridgeMode::Reliable,
    )
}

#[test]
fn async_examples_xid_asymmetric_server_receive_limit() -> TestResult {
    run_async_examples_echo_test(TestCase {
        name: "xid-server-receive-limit",
        client_extra_args: &["--xid", "--xid-receive-size", "64"],
        server_extra_args: &["--xid-receive-size", "8"],
        bridge_mode: BridgeMode::Reliable,
        timeout: TIMEOUT,
        expected_capture: None,
        preserve_captures_on_failure: true,
    })
}

#[test]
fn async_examples_xid_lost_all_responses_falls_back_with_cached_standard_offer() -> TestResult {
    run_async_examples_echo_test(TestCase {
        name: "xid-all-responses-lost",
        client_extra_args: &["--xid", "--no-extended", "--srt", "100ms"],
        server_extra_args: &["--xid-receive-size", "8"],
        bridge_mode: BridgeMode::Xid(XidFault::DropAllResponses),
        timeout: TIMEOUT,
        expected_capture: None,
        preserve_captures_on_failure: true,
    })
}

fn run_xid_test(
    name: &'static str,
    client_extra_args: &'static [&'static str],
    bridge_mode: BridgeMode,
) -> TestResult {
    run_async_examples_echo_test(TestCase {
        name,
        client_extra_args,
        server_extra_args: &[],
        bridge_mode,
        timeout: TIMEOUT,
        expected_capture: None,
        preserve_captures_on_failure: true,
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
        //"--experiments", "reset-retry-on-iframe-ack",
        "--experiments",
        "reset-retry-on-ack-update,resend-on-rr-command",
    ];
    #[allow(clippy::single_element_loop)]
    for seeds in [
        (0, 0),
        // These are always flaky.
        //(0x44, 0),
        //(0, 0x44),
        //(123, 321),
    ] {
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
    Xid(XidFault),
    Lossy {
        data_only: bool,
        drop_probability_percent: u8,
        client_to_server_seed: u64,
        server_to_client_seed: u64,
    },
}

#[derive(Clone, Copy, Debug)]
enum XidFault {
    DropCommand,
    DropResponse,
    DropAllResponses,
    Dm,
    Frmr,
    Ignore,
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

        exercise_echo(
            &mut client_stdin,
            &client_lines,
            &mut seen_stdout,
            test_case,
        )?;

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

        if let Some(expected) = test_case.expected_capture {
            assert_tshark_lines("client capture", &tshark_text(&client_capture)?, expected);
            assert_tshark_lines("server capture", &tshark_text(&server_capture)?, expected);
        }
        if test_case.client_extra_args.contains(&"--xid") {
            assert_xid_captures(test_case, &client_capture, &server_capture)?;
        }
        //return Err(Box::new(io::Error::other("fake break just to get captures")));
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

fn exercise_echo(
    stdin: &mut impl Write,
    lines: &mpsc::Receiver<String>,
    seen: &mut Vec<String>,
    case: TestCase,
) -> TestResult {
    recv_line_equal(lines, seen, "Welcome to the server!", case.timeout)?;
    // Ascending message lengths make packet traces easier to read.
    for msg in ["alpha", "bravoo", "charliee"] {
        stdin.write_all(msg.as_bytes())?;
        stdin.flush()?;
        recv_line_equal(lines, seen, &format!("Got <{msg}>"), case.timeout)?;
    }
    if case.server_extra_args.contains(&"--xid-receive-size") {
        stdin.write_all(b"abcdefghijklmnop")?;
        stdin.flush()?;
        let expected = if matches!(
            case.bridge_mode,
            BridgeMode::Xid(XidFault::DropAllResponses)
        ) {
            &["Got <abcdefghijklmnop>"][..]
        } else {
            &["Got <abcdefgh>", "Got <ijklmnop>"][..]
        };
        for expected in expected {
            recv_line_equal(lines, seen, expected, case.timeout)?;
        }
    }
    Ok(())
}

// These examples use two fixed, direct addresses, without digipeaters.
fn control(frame: &[u8]) -> u8 {
    frame[14] & !0x10
}

fn is_command(frame: &[u8]) -> bool {
    frame[6] & 0x80 != 0
}

fn read_capture(path: &Path) -> TestResult<Vec<Vec<u8>>> {
    let bytes = fs::read(path)?;
    if bytes.len() < 24 || bytes[..4] != [0xd4, 0xc3, 0xb2, 0xa1] {
        return Err(io::Error::other("expected little-endian pcap header").into());
    }
    assert_eq!(u32::from_le_bytes(bytes[20..24].try_into()?), 3);
    let mut remaining = &bytes[24..];
    let mut frames = Vec::new();
    while !remaining.is_empty() {
        if remaining.len() < 16 {
            return Err(io::Error::other("truncated pcap record header").into());
        }
        let size = usize::try_from(u32::from_le_bytes(remaining[8..12].try_into()?))?;
        remaining = &remaining[16..];
        let frame = remaining
            .get(..size)
            .ok_or_else(|| io::Error::other("truncated pcap frame"))?;
        assert!(frame.len() >= 15);
        assert_eq!(frame[6] & 1, 0);
        assert_eq!(frame[13] & 1, 1);
        frames.push(frame.to_vec());
        remaining = &remaining[size..];
    }
    Ok(frames)
}

fn assert_xid_captures(case: TestCase, client: &Path, server: &Path) -> TestResult {
    let client = read_capture(client)?;
    let server = read_capture(server)?;
    let fallback = matches!(
        case.bridge_mode,
        BridgeMode::Xid(
            XidFault::Dm | XidFault::Frmr | XidFault::Ignore | XidFault::DropAllResponses
        )
    );
    let extended = !fallback && !case.client_extra_args.contains(&"--no-extended");
    for (name, frames) in [("client", &client), ("server", &server)] {
        let setup = frames
            .iter()
            .position(|f| matches!(control(f), 0x2f | 0x6f))
            .ok_or_else(|| io::Error::other(format!("{name}: missing SABM(E)")))?;
        assert_eq!(
            control(&frames[setup]),
            if extended { 0x6f } else { 0x2f },
            "{name}: wrong setup mode"
        );
        assert!(
            frames[setup..].iter().all(|f| control(f) != 0xaf),
            "{name}: XID after setup"
        );
        for frame in frames {
            rax25::Packet::parse(frame, Some(extended))?;
        }
        if !fallback {
            let commands = frames[..setup]
                .iter()
                .filter(|f| control(f) == 0xaf && is_command(f))
                .count();
            let responses = frames[..setup]
                .iter()
                .filter(|f| control(f) == 0xaf && !is_command(f))
                .count();
            assert!(
                commands >= 1 && responses >= 1,
                "{name}: missing bidirectional XID exchange"
            );
            let first_command = frames
                .iter()
                .position(|f| control(f) == 0xaf && is_command(f))
                .unwrap();
            let first_response = frames
                .iter()
                .position(|f| control(f) == 0xaf && !is_command(f))
                .unwrap();
            assert!(first_command < first_response && first_response < setup);
            for frame in frames[..setup].iter().filter(|f| control(f) == 0xaf) {
                assert_ne!(frame[14] & 0x10, 0, "XID must carry P/F");
                assert!(frame.len() > 15, "XID must carry parameters");
            }
        }
        assert!(
            frames[setup..].iter().any(|f| control(f) == 0x43),
            "{name}: missing EOF DISC"
        );
        assert_eq!(
            control(frames.last().unwrap()),
            0x63,
            "{name}: missing final UA"
        );
        assert_receive_limits(case, frames, name, extended);
    }
    assert_xid_fault(case.bridge_mode, &client, &server);
    Ok(())
}

fn assert_receive_limits(case: TestCase, frames: &[Vec<u8>], name: &str, extended: bool) {
    if matches!(
        case.bridge_mode,
        BridgeMode::Xid(XidFault::DropAllResponses)
    ) {
        let payloads: Vec<_> = frames
            .iter()
            .filter(|f| f[13] & 0x1e == 2 && f[14] & 1 == 0)
            .map(|f| &f[16..])
            .collect();
        assert_eq!(payloads.concat(), b"alphabravoocharlieeabcdefghijklmnop");
        assert_eq!(
            payloads.last().copied(),
            Some(b"abcdefghijklmnop".as_slice()),
            "{name}: fallback must send the entire 16-byte legacy frame"
        );
    } else if case.server_extra_args.contains(&"--xid-receive-size") {
        let client_payloads: Vec<_> = frames
            .iter()
            .filter(|f| f[13] & 0x1e == 2 && f[14] & 1 == 0)
            .map(|f| &f[17..])
            .collect();
        assert!(client_payloads.iter().all(|p| p.len() <= 8));
        assert_eq!(
            client_payloads.concat(),
            b"alphabravoocharlieeabcdefghijklmnop"
        );
        assert_eq!(
            &client_payloads[client_payloads.len() - 2..],
            &[b"abcdefgh".as_slice(), b"ijklmnop".as_slice()]
        );
        let welcome = frames
            .iter()
            .find(|f| f[13] & 0x1e == 4 && f[14] & 1 == 0)
            .unwrap();
        assert_eq!(
            &welcome[17..],
            b"Welcome to the server!\n",
            "larger client limit must not restrict server to 8 bytes"
        );
    } else if case.client_extra_args.contains(&"--xid-receive-size") {
        let mut welcome = Vec::new();
        let mut count = 0;
        for frame in frames
            .iter()
            .filter(|f| f[13] & 0x1e == 4 && f[14] & 1 == 0)
        {
            let payload = &frame[if extended { 17 } else { 16 }..];
            assert!(payload.len() <= 8, "{name}: peer receive limit exceeded");
            if welcome.len() < b"Welcome to the server!\n".len() {
                welcome.extend_from_slice(payload);
                count += 1;
            }
        }
        assert_eq!(welcome, b"Welcome to the server!\n");
        assert!(count >= 3, "{name}: welcome was not split");
    }
}

fn assert_xid_fault(mode: BridgeMode, client: &[Vec<u8>], server: &[Vec<u8>]) {
    let count = |frames: &[Vec<u8>], command| {
        frames
            .iter()
            .filter(|f| control(f) == 0xaf && is_command(f) == command)
            .count()
    };
    match mode {
        BridgeMode::Xid(XidFault::DropCommand) => {
            assert!(count(client, true) >= 2);
            assert_eq!(count(client, true), count(server, true) + 1);
        }
        BridgeMode::Xid(XidFault::DropResponse) => {
            assert!(count(client, true) >= 2);
            assert_eq!(count(server, false), count(client, false) + 1);
        }
        BridgeMode::Xid(XidFault::DropAllResponses) => {
            assert!(
                count(client, true) >= 2,
                "must retry before timeout fallback"
            );
            assert_eq!(count(client, true), count(server, true));
            assert_eq!(count(server, true), count(server, false));
            assert_eq!(count(client, false), 0);
            for frame in server
                .iter()
                .filter(|f| control(f) == 0xaf && !is_command(f))
            {
                let parameters = rax25::xid::XidParameters::parse(&frame[15..]).unwrap();
                assert_eq!(
                    parameters.receive_length_bits,
                    Some(64),
                    "server must advertise and cache its 8-byte receive proposal"
                );
            }
        }
        BridgeMode::Xid(fault @ (XidFault::Dm | XidFault::Frmr | XidFault::Ignore)) => {
            assert!(count(client, true) >= 1);
            assert_eq!(count(server, true), 0);
            assert_eq!(count(client, false), 0);
            if matches!(fault, XidFault::Ignore) {
                assert!(
                    count(client, true) >= 2,
                    "timeout fallback must exhaust retries"
                );
            } else {
                let rejection = if matches!(fault, XidFault::Dm) {
                    0x0f
                } else {
                    0x87
                };
                let setup = client.iter().position(|f| control(f) == 0x2f).unwrap();
                assert!(
                    client[..setup]
                        .iter()
                        .any(|f| control(f) == rejection && !is_command(f))
                );
            }
        }
        _ => {
            // Endpoints can observe opposite-direction frames in a different
            // interleaving. Each direction must still match byte for byte.
            for ssid in [2, 4] {
                let from = |frames: &[Vec<u8>]| {
                    frames
                        .iter()
                        .filter(|f| f[13] & 0x1e == ssid)
                        .cloned()
                        .collect::<Vec<_>>()
                };
                assert_eq!(
                    from(client),
                    from(server),
                    "reliable bridge captures differ"
                );
            }
        }
    }
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
            "-F",
            "async",
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
    let actual_lines: Vec<_> = actual.lines().map(normalize_tshark_addresses).collect();
    let expected_lines: Vec<_> = expected
        .iter()
        .map(|line| normalize_tshark_addresses(line))
        .collect();
    let actual: Vec<_> = actual_lines.iter().map(String::as_str).collect();
    let expected: Vec<_> = expected_lines.iter().map(String::as_str).collect();
    assert!(
        actual == expected,
        "{name} did not match expected tshark output\n{}",
        unified_diff(name, &expected, &actual)
    );
}

fn normalize_tshark_addresses(line: &str) -> String {
    // Tshark versions render AX.25 addresses as either hex bytes or callsigns.
    line.split('|')
        .enumerate()
        .map(|(index, field)| {
            if matches!(index, 1 | 2) {
                let bytes: Result<Vec<_>, _> = field
                    .split(':')
                    .map(|byte| u8::from_str_radix(byte, 16))
                    .collect();
                if let Ok(bytes) = bytes
                    && let Ok(address) = rax25::Addr::parse(&bytes)
                {
                    return address.call().to_owned();
                }
            }
            field.to_owned()
        })
        .collect::<Vec<_>>()
        .join("|")
}

#[test]
fn tshark_address_formats_compare_equally() {
    let raw = "1|9a:60:a8:a6:a8:40:63|9a:60:a8:a6:a8:40:e4|0x3f|||U P, func=SABM";
    let callsigns = "1|M0TST-1|M0TST-2|0x3f|||U P, func=SABM";
    assert_eq!(normalize_tshark_addresses(raw), callsigns);
    assert_eq!(normalize_tshark_addresses(callsigns), callsigns);
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

    if let BridgeMode::Xid(fault) = mode {
        let to_server = thread::spawn(move || copy_xid_frames(client_read, server, fault, true));
        let to_client = thread::spawn(move || copy_xid_frames(server_read, client, fault, false));
        to_server
            .join()
            .map_err(|_| io::Error::other("XID bridge panicked"))??;
        to_client
            .join()
            .map_err(|_| io::Error::other("XID bridge panicked"))??;
        return Ok(());
    }

    let (client_to_server_loss, server_to_client_loss) = match mode {
        BridgeMode::Reliable => (None, None),
        BridgeMode::Xid(_) => unreachable!(),
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

fn copy_xid_frames(
    mut src: TcpStream,
    mut dst: TcpStream,
    fault: XidFault,
    client_to_server: bool,
) -> io::Result<()> {
    let mut frame = Vec::new();
    let mut dropped = false;
    let mut byte = [0];
    while src.read(&mut byte)? != 0 {
        frame.push(byte[0]);
        if byte[0] != 0xc0 || frame.len() == 1 {
            continue;
        }
        if frame.len() == 2 {
            frame.pop();
            continue;
        }
        let raw = rax25::unescape(&frame[2..frame.len() - 1]);
        let xid = frame[1].trailing_zeros() >= 4 && raw.len() >= 15 && control(&raw) == 0xaf;
        let drop = xid
            && match fault {
                XidFault::DropCommand => client_to_server && !dropped,
                XidFault::DropResponse => !client_to_server && !dropped,
                XidFault::DropAllResponses => !client_to_server,
                XidFault::Dm | XidFault::Frmr | XidFault::Ignore => client_to_server,
            };
        if drop {
            dropped = true;
            if matches!(fault, XidFault::Dm | XidFault::Frmr) {
                let mut reply = raw[7..14].to_vec();
                reply[6] &= !1;
                reply.extend_from_slice(&raw[..7]);
                reply[13] |= 1;
                reply.push(if matches!(fault, XidFault::Dm) {
                    0x1f
                } else {
                    0x97
                });
                if matches!(fault, XidFault::Frmr) {
                    reply.extend_from_slice(&[raw[14], 0, 1]);
                }
                let mut kiss = vec![0xc0, 0];
                for byte in reply {
                    match byte {
                        0xc0 => kiss.extend_from_slice(&[0xdb, 0xdc]),
                        0xdb => kiss.extend_from_slice(&[0xdb, 0xdd]),
                        _ => kiss.push(byte),
                    }
                }
                kiss.push(0xc0);
                src.write_all(&kiss)?;
            }
        } else {
            dst.write_all(&frame)?;
        }
        frame.clear();
    }
    if !frame.is_empty() {
        return Err(io::Error::other("truncated KISS frame"));
    }
    dst.shutdown(Shutdown::Write)
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
