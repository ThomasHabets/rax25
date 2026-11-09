//! Single-port AGW packet engine using an external KISS modem.
use std::collections::{HashMap, VecDeque};

use agw::r#async::AGWServer;
use agw::{Baud, Packet, Pid, Port, PortCaps, PortInfo, PortsInfo};
use anyhow::{Result, bail};
use clap::{ArgGroup, Parser};
use log::info;
use rax25::{
    Callsign,
    engine::{Command, LinkEvent, Notification, OwnerId, PacketEngine, Route},
};
use tokio::sync::{mpsc, oneshot};
use tokio_serial::SerialPortBuilderExt;

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// AGW server over a shared KISS modem.
#[derive(Parser)]
#[command(group(ArgGroup::new("modem").required(true).args(["dev", "tcp"])))]
struct Opt {
    /// Serial KISS device (mutually exclusive with --tcp).
    #[arg(long, short)]
    dev: Option<std::path::PathBuf>,

    /// KISS modem TCP address, such as localhost:8001.
    #[arg(long, short)]
    tcp: Option<String>,

    /// Serial interface baud rate, not the over-the-air radio rate.
    #[arg(long, short, default_value_t = 9600)]
    baud: u32,

    /// TCP address to listen on for AGW application clients.
    #[arg(long, short)]
    listen: String,

    /// Use modulo-128 extended AX.25 for outgoing connections.
    #[arg(long, short)]
    extended: bool,

    /// Negotiate link parameters with XID before outgoing connections.
    /// Use --extended to request modulo-128; otherwise request modulo-8.
    #[arg(long)]
    xid: bool,

    /// Capture sent and received AX.25 packets to a new pcap file.
    #[arg(long)]
    capture: Option<std::path::PathBuf>,

    /// Log level for stderr diagnostics.
    #[arg(short = 'v', long = "log-level", value_enum, default_value = "info")]
    log_level: LogLevel,
}

// An AGW packet received from an AGW client, or EOF.
enum Input {
    Reply(OwnerId, Packet),
    Gone(OwnerId),
}

// An AGW client.
struct Client {
    tx: Option<mpsc::Sender<Packet>>,
    reader_task: tokio::task::JoinHandle<()>,
    writer_task: tokio::task::JoinHandle<()>,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.reader_task.abort();
        self.writer_task.abort();
    }
}

impl Client {
    async fn finish(mut self) {
        self.reader_task.abort();
        self.tx.take();
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(1), &mut self.writer_task).await;
    }
}

fn route(src: &agw::Call, dst: &agw::Call) -> Result<Route> {
    Ok(Route {
        local: Callsign::new(src.as_str())?,
        remote: Callsign::new(dst.as_str())?,
    })
}

fn call(c: &Callsign) -> Result<agw::Call> {
    Ok(agw::Call::from_bytes(c.call().as_bytes())?)
}

async fn submit(engine: &mpsc::Sender<Command>, command: Command) -> Result<()> {
    engine
        .send(command)
        .await
        .map_err(|_| anyhow::anyhow!("modem engine stopped"))
}

// Process an AGW packet from the client.
//
// Returns a packet to be sent back, if any.
#[allow(clippy::too_many_lines)]
async fn request(
    owner: OwnerId,
    packet: Packet,
    engine: &mpsc::Sender<Command>,
    extended: bool,
) -> Result<Option<Packet>> {
    Ok(match packet {
        Packet::VersionQuery => Some(Packet::VersionReply {
            major: 2005,
            minor: 127,
        }),
        Packet::PortInfoQuery => Some(Packet::PortInfoReply(PortsInfo {
            count: 1,
            ports: vec![PortInfo {
                port: Port(1),
                descr: "rax25 KISS channel 0".into(),
            }],
        })),
        Packet::PortCapQuery(Port(1)) => {
            let (reply, rx) = oneshot::channel();
            submit(engine, Command::Active(reply)).await?;
            // KISS does not report radio settings. These are conventional
            // defaults, not measurements or inferred serial baud rates.
            Some(Packet::PortCapReply {
                port: Port(1),
                caps: PortCaps {
                    rate: Baud::B1200,
                    traffic_level: None,
                    tx_delay: 30,
                    tx_tail: 10,
                    persist: 63,
                    slot_time: 10,
                    max_frame: if extended { 32 } else { 4 },
                    active_connections: u8::try_from(rx.await?).unwrap_or(u8::MAX),
                    bytes_per_2min: 0,
                },
            })
        }
        Packet::RegisterCallsign(port, call) => {
            let success = port == Port(1) && {
                if let Ok(local) = Callsign::new(call.as_str()) {
                    let (reply, rx) = oneshot::channel();
                    submit(
                        engine,
                        Command::Listen {
                            owner,
                            local,
                            reply,
                        },
                    )
                    .await?;
                    rx.await?
                } else {
                    false
                }
            };
            Some(Packet::RegisterCallsignReply {
                port,
                call,
                success,
            })
        }
        Packet::Connect {
            port,
            pid,
            src,
            dst,
        } => {
            if port != Port(1) || !matches!(pid, Pid(0 | 0xf0)) {
                Some(Packet::ConnectionFailed {
                    port,
                    pid,
                    src: dst,
                    dst: src,
                    message: "unsupported port or PID".into(),
                })
            } else {
                submit(
                    engine,
                    Command::Connect {
                        owner,
                        route: route(&src, &dst)?,
                        via: vec![],
                        extended,
                    },
                )
                .await?;
                None
            }
        }
        Packet::ConnectVia {
            port: Port(1),
            pid: Pid(0 | 0xf0),
            src,
            dst,
            via,
        } => {
            let via = via
                .iter()
                .map(|c| rax25::Addr::new(c.as_str()))
                .collect::<rax25::Result<Vec<_>>>()?;
            if via.len() > 8 {
                bail!("too many digipeaters");
            }
            submit(
                engine,
                Command::Connect {
                    owner,
                    route: route(&src, &dst)?,
                    via,
                    extended,
                },
            )
            .await?;
            None
        }
        Packet::Data {
            port: Port(1),
            pid: Pid(0 | 0xf0),
            src,
            dst,
            data,
        } => {
            submit(
                engine,
                Command::Write {
                    owner,
                    route: route(&src, &dst)?,
                    bytes: data,
                },
            )
            .await?;
            None
        }
        Packet::ConnectViaMarked {
            port: Port(1),
            pid: Pid(0 | 0xf0),
            src,
            dst,
            via,
        } => {
            // CALL* seen markers are a Dire Wolf extension, not AGWPE syntax.
            let via = via
                .iter()
                .map(|hop| {
                    rax25::Addr::new(hop.callsign().as_str())
                        .map(|addr| addr.with_highbit(hop.is_seen()))
                })
                .collect::<rax25::Result<Vec<_>>>()?;
            if via.len() > 8 {
                bail!("too many digipeaters");
            }
            submit(
                engine,
                Command::Connect {
                    owner,
                    route: route(&src, &dst)?,
                    via,
                    extended,
                },
            )
            .await?;
            None
        }
        Packet::Disconnect {
            port: Port(1),
            src,
            dst,
            ..
        } => {
            submit(
                engine,
                Command::Disconnect {
                    owner,
                    route: route(&src, &dst)?,
                },
            )
            .await?;
            None
        }
        Packet::Unproto {
            port: Port(1),
            pid,
            src,
            dst,
            data,
        } => {
            submit(
                engine,
                Command::Ui {
                    local: Callsign::new(src.as_str())?,
                    remote: Callsign::new(dst.as_str())?,
                    pid: pid.0,
                    bytes: data,
                },
            )
            .await?;
            None
        }
        Packet::FramesOutstandingPortQuery(Port(1)) => {
            let (reply, rx) = oneshot::channel();
            submit(
                engine,
                Command::Pending {
                    owner,
                    route: None,
                    reply,
                },
            )
            .await?;
            Some(Packet::FramesOutstandingPortReply(Port(1), rx.await?))
        }
        Packet::UnregisterCallsign(Port(1), src) => {
            submit(
                engine,
                Command::Unlisten {
                    owner,
                    local: Callsign::new(src.as_str())?,
                },
            )
            .await?;
            None
        }
        Packet::FramesOutstandingConnectionQuery {
            port: Port(1),
            src,
            dst,
        } => {
            let (reply, rx) = oneshot::channel();
            submit(
                engine,
                Command::Pending {
                    owner,
                    route: Some(route(&src, &dst)?),
                    reply,
                },
            )
            .await?;
            Some(Packet::FramesOutstandingConnectionReply {
                port: Port(1),
                src,
                dst,
                count: u32::try_from(rx.await?)?,
            })
        }
        other => {
            log::warn!("Unsupported AGW request: {other:?}");
            None
        }
    })
}

// Process an update from the engine.
//
// Return a packet to to be sent to the AGW client in response.
fn notification(n: Notification) -> Result<(OwnerId, Packet)> {
    let src = call(&n.route.remote)?;
    let dst = call(&n.route.local)?;
    let port = Port(1);
    let pid = Pid(0xf0);
    let packet = match n.event {
        LinkEvent::Connected { incoming: true } => Packet::IncomingConnect {
            port,
            pid,
            src,
            dst,
        },
        LinkEvent::Connected { incoming: false } => Packet::ConnectionEstablished {
            port,
            pid,
            src,
            dst,
        },
        LinkEvent::Data(data) => Packet::Data {
            port,
            pid,
            src,
            dst,
            data,
        },
        LinkEvent::Closed => Packet::Disconnect {
            port,
            pid,
            src,
            dst,
        },
        LinkEvent::Failed => Packet::ConnectionFailed {
            port,
            pid,
            src,
            dst,
            message: "AX.25 connection failed".into(),
        },
    };
    Ok((n.owner, packet))
}

// Run the AGW server loop, forever.
async fn serve(
    listener: tokio::net::TcpListener,
    engine: mpsc::Sender<Command>,
    mut events: mpsc::Receiver<Notification>,
    extended: bool,
) -> Result<()> {
    // Comms from clients to this main loop.
    let (tx, mut rx) = mpsc::channel(256);

    // All connected or draining clients.
    let mut clients: HashMap<OwnerId, Client> = HashMap::new();

    // Clients in cleanup. We need to tell the engine to unregister any
    // associated callsigns.
    let mut cleanup = VecDeque::new();

    // Next owner ID.
    let mut next = 0_u64;
    loop {
        let output = tokio::select! {

            // New client.
            accepted = listener.accept() => {
                let (socket, peer) = accepted?;
                if clients.len() >= 256 || cleanup.len() >= 256 {
                    info!("Client {peer:?} dropped due to connection limit exceeded");
                    continue;
                }
                next = next.checked_add(1).ok_or_else(|| anyhow::anyhow!("client ID overflow"))?;
                info!("Client {peer:?} id {next} connected");
                let id = OwnerId(next);
                let (mut reader, mut writer) = AGWServer::new(socket).into_split();

                // For sending out AGW data on the connection.
                let (out, mut outgoing) = mpsc::channel(64);

                // Channels back from the AGW connection reader to the input
                // processing path, and directly to the engine.
                let input = tx.clone();
                let commands = engine.clone();

                // Just read AGW packets and send them or events over the
                // channels.
                let read = tokio::spawn(async move {
                    while let Ok(packet) = reader.recv().await {
                        match request(id, packet, &commands, extended).await {
                            Ok(Some(reply)) => if input.send(Input::Reply(id, reply)).await.is_err() {
                                return;
                            },
                            Ok(None) => {},
                            Err(error) => { log::warn!("Client {id}: {error}"); break; }
                        }
                    }
                    // If the receiver is gone, that just means the connection
                    // is tearing down while the whole process is tearing down,
                    // so drop the error.
                    let _ = input.send(Input::Gone(id)).await;
                });

                // The writer can also get "input" in the form of the client
                // going away during write.
                let input = tx.clone();
                let write = tokio::spawn(async move {
                    while let Some(packet) = outgoing.recv().await {
                        if writer.send(&packet).await.is_err() { break; }
                    }
                    let _ = input.send(Input::Gone(id)).await;
                });
                clients.insert(id, Client { tx: Some(out), reader_task: read, writer_task: write });
                None
            }

            // A notable event happened in the AX.25 processing, such as a
            // connection having been established.
            event = events.recv() => {
                let Some(event) = event else {
                    for (_, client) in clients.drain() {
                        client.finish().await;
                    }
                    return Ok(());
                };
                Some(notification(event)?)
            }

            // Notify engine to clean up disconnected clients.
            permit = engine.reserve(), if !cleanup.is_empty() => {
                // Keep draining link events while cleanup waits for command
                // capacity; awaiting it inline could deadlock a full engine.
                if let Ok(permit) = permit {
                    permit.send(cleanup.pop_front().expect("nonempty cleanup queue"));
                } else {
                    cleanup.clear();
                }
                None
            }

            // A connection is conveying something that happened on the
            // connection.
            input = rx.recv() => {
                match input {
                    Some(Input::Gone(id)) => {
                        if clients.remove(&id).is_some() {
                            cleanup.push_back(Command::RemoveOwner(id));
                        }
                        None
                    }
                    Some(Input::Reply(id, packet)) => if clients.contains_key(&id) {
                        Some((id, packet))
                    } else {
                        None
                    },
                    None => None,
                }
            }
        };

        // If the above resulted in a request to send AGW data to an AGW client,
        // then send it.
        if let Some((id, packet)) = output
            && let Some(client) = clients.get(&id)
            && client
                .tx
                .as_ref()
                .is_some_and(|tx| tx.try_send(packet).is_err())
        {
            clients.remove(&id);
            cleanup.push_back(Command::RemoveOwner(id));
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    stderrlog::new()
        .module("rax25")
        .module(module_path!())
        .verbosity(opt.log_level as usize)
        .init()?;
    let port = if let Some(dev) = opt.dev {
        rax25::r#async::PortType::Serial(
            tokio_serial::new(
                dev.to_str()
                    .ok_or_else(|| anyhow::anyhow!("non-UTF8 device"))?,
                opt.baud,
            )
            .open_native_async()?,
        )
    } else {
        rax25::r#async::PortType::Tcp(
            tokio::net::TcpStream::connect(opt.tcp.as_deref().unwrap_or_default()).await?,
        )
    };
    let listener = tokio::net::TcpListener::bind(&opt.listen).await?;
    let (mut engine, commands, events) = PacketEngine::new();
    if opt.xid {
        engine.set_xid_config(rax25::XidConfig::default())?;
    }
    if let Some(path) = opt.capture {
        engine.capture(path)?;
    }
    let modem = engine.run(port);
    let server = serve(listener, commands, events, opt.extended);
    tokio::pin!(modem, server);
    tokio::select! {
        result = &mut modem => {
            // Drain final link notifications before closing application sockets.
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), &mut server).await;
            result?;
        },
        result = &mut server => result?,
        result = tokio::signal::ctrl_c() => result?,
    }
    Ok(())
}
