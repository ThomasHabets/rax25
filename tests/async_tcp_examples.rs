//! Check that async server and client can talk to each other, in the no-error
//! case.
//!
//! This whole thing was AI-coded. It looks right, and I fixed a thing or two,
//! but being a test I have not super validated it.
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn async_examples_echo_over_tcp_and_exit_on_client_eof() -> TestResult {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    build_examples(&manifest_dir)?;

    let bridge = start_kiss_bridge()?;
    let server_endpoint = format!("tcp://{}", bridge.server_addr);
    let client_endpoint = format!("tcp://{}", bridge.client_addr);

    let server_exe = example_exe(&manifest_dir, "async_server");
    let client_exe = example_exe(&manifest_dir, "async_client");

    let mut server = ChildGuard::new(
        Command::new(&server_exe)
            .args(["-p", &server_endpoint, "-s", "M0TST-2"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| io::Error::other(format!("spawning {server_exe:?}: {e}")))?,
    );

    let mut client = ChildGuard::new(
        Command::new(&client_exe)
            .args(["-p", &client_endpoint, "-s", "M0TST-1", "M0TST-2"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| io::Error::other(format!("spawning {client_exe:?}: {e}")))?,
    );

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
        Duration::from_secs(10),
    )?;

    for msg in ["alpha", "bravo", "charlie"] {
        client_stdin.write_all(msg.as_bytes())?;
        client_stdin.flush()?;
        recv_line_equal(
            &client_lines,
            &mut seen_stdout,
            &format!("Got <{msg}>"),
            Duration::from_secs(10),
        )?;
    }

    drop(client_stdin);
    wait_for_success("async_client", &mut client, Duration::from_secs(10))?;
    wait_for_success("async_server", &mut server, Duration::from_secs(10))?;

    stdout_reader
        .join()
        .map_err(|_| io::Error::other("client stdout reader panicked"))?;
    bridge
        .done
        .recv_timeout(Duration::from_secs(2))
        .map_err(|_| io::Error::other("KISS bridge did not stop"))?
        .map_err(io::Error::other)?;

    Ok(())
}

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

struct KissBridge {
    client_addr: std::net::SocketAddr,
    server_addr: std::net::SocketAddr,
    done: mpsc::Receiver<Result<(), String>>,
}

fn start_kiss_bridge() -> TestResult<KissBridge> {
    let client_listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| io::Error::other(format!("binding client KISS listener: {e}")))?;
    let server_listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| io::Error::other(format!("binding server KISS listener: {e}")))?;
    let client_addr = client_listener.local_addr()?;
    let server_addr = server_listener.local_addr()?;
    let (done_tx, done) = mpsc::channel();

    thread::spawn(move || {
        let result = run_kiss_bridge(client_listener, server_listener).map_err(|e| e.to_string());
        let _ = done_tx.send(result);
    });

    Ok(KissBridge {
        client_addr,
        server_addr,
        done,
    })
}

#[allow(clippy::needless_pass_by_value)]
fn run_kiss_bridge(client_listener: TcpListener, server_listener: TcpListener) -> io::Result<()> {
    let (client, _) = client_listener.accept()?;
    let (server, _) = server_listener.accept()?;
    client.set_nodelay(true)?;
    server.set_nodelay(true)?;

    let client_read = client.try_clone()?;
    let server_read = server.try_clone()?;

    let to_server = thread::spawn(move || copy_until_eof(client_read, server));
    let to_client = thread::spawn(move || copy_until_eof(server_read, client));

    to_server
        .join()
        .map_err(|_| io::Error::other("client-to-server bridge panicked"))?;
    to_client
        .join()
        .map_err(|_| io::Error::other("server-to-client bridge panicked"))?;
    Ok(())
}

fn copy_until_eof(mut src: TcpStream, mut dst: TcpStream) {
    let _ = io::copy(&mut src, &mut dst);
    let _ = dst.shutdown(Shutdown::Write);
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
