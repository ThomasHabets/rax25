#![cfg(feature = "async")]
use agw::r#async::AGWServer;
use agw::{Call, Packet, Pid, Port};
use anyhow::{Result, ensure};
use rax25::{
    Callsign,
    r#async::{ConnectionBuilder, PortType},
};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn call(s: &str) -> Call {
    Call::from_bytes(s.as_bytes()).unwrap()
}

async fn exchange(
    binary: &std::path::Path,
    extended: bool,
    outgoing: bool,
    xid: bool,
) -> Result<()> {
    let kiss = TcpListener::bind("127.0.0.1:0").await?;
    let address = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let mut cmd = Command::new(binary);
    let capture = binary.parent().unwrap().join(format!(
        "agw-test-{}-{extended}-{outgoing}-{xid}.pcap",
        std::process::id()
    ));
    cmd.arg("--capture").arg(&capture);
    if xid {
        cmd.arg("--xid");
    }
    cmd.args([
        "--tcp",
        &kiss.local_addr()?.to_string(),
        "--listen",
        &address.to_string(),
    ]);
    if extended {
        cmd.arg("-e");
    }
    let _process = Process(cmd.stdout(Stdio::null()).spawn()?);
    let (modem, _) = kiss.accept().await?;
    let socket = loop {
        match TcpStream::connect(address).await {
            Ok(socket) => break socket,
            Err(_) => sleep(Duration::from_millis(10)).await,
        }
    };
    let mut client = AGWServer::new(socket);
    prepare(&mut client, address).await?;
    let native = async {
        let mut builder = ConnectionBuilder::new(Callsign::new("REMOTE")?, PortType::Tcp(modem))?
            .extended(Some(extended));
        if xid {
            builder = builder.xid(rax25::XidConfig::default());
        }
        let mut native = if outgoing {
            builder.accept().await?
        } else {
            builder.connect(Callsign::new("LOCAL")?).await?
        };
        native.write(&[0, 0xc0, 0xdb, 255]).await?;
        ensure!(native.read().await? == [0, 0xc0, 0xdb, 255]);
        native.disconnect().await?;
        Ok::<_, anyhow::Error>(())
    };
    let application = async {
        if outgoing {
            client
                .send(&Packet::Connect {
                    port: Port(1),
                    pid: Pid(0xf0),
                    src: call("LOCAL"),
                    dst: call("REMOTE"),
                })
                .await?;
        }
        let established = client.recv().await?;
        ensure!(if outgoing {
            matches!(established, Packet::ConnectionEstablished { .. })
        } else {
            matches!(established, Packet::IncomingConnect { .. })
        });
        let Packet::Data { src, dst, data, .. } = client.recv().await? else {
            anyhow::bail!("expected connected data");
        };
        ensure!(src == call("REMOTE") && dst == call("LOCAL"));
        client
            .send(&Packet::Data {
                port: Port(1),
                pid: Pid(0xf0),
                src: dst,
                dst: src,
                data,
            })
            .await?;
        ensure!(matches!(client.recv().await?, Packet::Disconnect { .. }));
        Ok::<_, anyhow::Error>(())
    };
    tokio::try_join!(native, application)?;
    check_capture(&capture, extended, xid)?;
    std::fs::remove_file(capture)?;
    Ok(())
}

fn check_capture(capture: &std::path::Path, extended: bool, xid: bool) -> Result<()> {
    let bytes = std::fs::read(capture)?;
    ensure!(bytes.len() >= 24 && bytes[..4] == [0xd4, 0xc3, 0xb2, 0xa1]);
    let mut frames = Vec::new();
    let mut records = &bytes[24..];
    while !records.is_empty() {
        ensure!(records.len() >= 16, "truncated pcap record");
        let length = u32::from_le_bytes(records[8..12].try_into()?) as usize;
        ensure!(records.len() >= 16 + length, "truncated pcap frame");
        let frame = &records[16..16 + length];
        let packet = rax25::Packet::parse(frame, Some(extended))?;
        frames.push((rax25::Addr::parse(&frame[7..14])?, packet));
        records = &records[16 + length..];
    }
    for source in ["LOCAL", "REMOTE"] {
        ensure!(
            frames.iter().any(|(address, packet)| {
                address.callsign().call() == source
                    && matches!(packet.packet_type(), rax25::PacketType::Iframe(_))
            }),
            "missing captured data from {source}"
        );
    }
    let xid_frames: Vec<_> = frames
        .iter()
        .filter(|(_, packet)| matches!(packet.packet_type(), rax25::PacketType::Xid(_)))
        .collect();
    ensure!(
        xid_frames.len() == if xid { 2 } else { 0 },
        "unexpected XID exchange"
    );
    if xid {
        ensure!(matches!(
            frames[0].1.packet_type(),
            rax25::PacketType::Xid(_)
        ));
        ensure!(matches!(
            frames[1].1.packet_type(),
            rax25::PacketType::Xid(_)
        ));
        for (_, packet) in xid_frames {
            ensure!(
                matches!(packet.packet_type(), rax25::PacketType::Xid(reply) if reply.parameters.is_some()),
                "missing XID parameters"
            );
        }
    }
    Ok(())
}

async fn prepare(client: &mut AGWServer, address: std::net::SocketAddr) -> Result<()> {
    let bytes = Packet::VersionQuery.serialize()?;
    client.get_mut().write_all(&bytes[..10]).await?;
    sleep(Duration::from_millis(10)).await;
    client.get_mut().write_all(&bytes[10..]).await?;
    ensure!(matches!(client.recv().await?, Packet::VersionReply { .. }));
    client.send(&Packet::VersionQuery).await?;
    ensure!(matches!(client.recv().await?, Packet::VersionReply { .. }));
    client.send(&Packet::PortInfoQuery).await?;
    ensure!(
        matches!(client.recv().await?, Packet::PortInfoReply(info) if info.count == 1 && info.ports[0].port == Port(1))
    );
    client
        .send(&Packet::RegisterCallsign(Port(1), call("LOCAL")))
        .await?;
    ensure!(matches!(
        client.recv().await?,
        Packet::RegisterCallsignReply { success: true, .. }
    ));
    let mut second = AGWServer::new(TcpStream::connect(address).await?);
    second
        .send(&Packet::RegisterCallsign(Port(1), call("LOCAL")))
        .await?;
    ensure!(matches!(
        second.recv().await?,
        Packet::RegisterCallsignReply { success: false, .. }
    ));
    client
        .send(&Packet::UnregisterCallsign(Port(1), call("LOCAL")))
        .await?;
    client.send(&Packet::VersionQuery).await?;
    let _ = client.recv().await?;
    second
        .send(&Packet::RegisterCallsign(Port(1), call("LOCAL")))
        .await?;
    ensure!(matches!(
        second.recv().await?,
        Packet::RegisterCallsignReply { success: true, .. }
    ));
    second
        .send(&Packet::UnregisterCallsign(Port(1), call("LOCAL")))
        .await?;
    second.send(&Packet::VersionQuery).await?;
    let _ = second.recv().await?;
    client
        .send(&Packet::RegisterCallsign(Port(1), call("LOCAL")))
        .await?;
    ensure!(matches!(
        client.recv().await?,
        Packet::RegisterCallsignReply { success: true, .. }
    ));
    Ok(())
}

#[tokio::test]
async fn agw_example_incoming_and_outgoing_native_interop() -> Result<()> {
    ensure!(
        Command::new("cargo")
            .args(["build", "--features", "async", "--example", "agw"])
            .status()?
            .success()
    );
    let root = std::env::var_os("CARGO_MANIFEST_DIR")
        .map_or(std::env::current_dir()?, std::path::PathBuf::from);
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| root.join("target"), std::path::PathBuf::from);
    let target = if target.is_absolute() {
        target
    } else {
        root.join(target)
    };
    let binary = target.join("debug/examples/agw");
    for extended in [false, true] {
        for outgoing in [false, true] {
            for xid in [false, true] {
                timeout(
                    Duration::from_secs(15),
                    exchange(&binary, extended, outgoing, xid),
                )
                .await??;
            }
        }
    }
    Ok(())
}
