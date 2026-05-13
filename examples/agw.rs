#![allow(clippy::similar_names)]
//! AGW server.
// TODO: move this to be a binary, not an example.

use anyhow::Result;
use clap::Parser;
use log::{debug, info, warn};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio_serial::SerialPortBuilderExt;

use rax25::r#async::PortType;
//use rax25::r#async::{ConnectionBuilder, PortType};
use agw::r#async::AGWServer;

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// AGW server.
#[derive(Parser)]
struct Opt {
    /// Serial KISS device.
    // TODO: merge -d and -k
    #[arg(long, short)]
    dev: Option<std::path::PathBuf>,

    /// KISS TCP address.
    #[arg(long, short)]
    kiss: Option<String>,

    /// Baud rate.
    #[arg(long, short, default_value_t = 9600)]
    baud: u32,

    /// TCP address to listen on for AGW clients.
    #[arg(long, short)]
    listen: String,

    /// Log level for stderr diagnostics.
    #[arg(short = 'v', long = "log-level", value_enum, default_value = "info")]
    log_level: LogLevel,
}

async fn handle_client(mut stream: AGWServer, mut modem: ModemLink) -> Result<()> {
    loop {
        tokio::select! {
            packet = stream.recv() => {
                let packet = match packet {
                    Ok(p) => p,
                    Err(agw::Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e.into()),
                };
                debug!("Got packet from AGW client: {packet:?}");
                #[allow(clippy::single_match)]
                match packet {
                    agw::Packet::VersionQuery => {
                        stream.send(&agw::Packet::VersionReply {
                            major: 2005, // TODO: magic.
                            minor: 127,
                        }).await?;
                    },
                    _ => {}
                }
            }
            packet = modem.recv() => {
                let packet = packet?;
                debug!("Got packet from modem: {packet:?}");
                modem.send(vec![]).await?;
            }
        }
    }
    info!("Connection ended normally");
    Ok(())
}

#[derive(Clone)]
struct ModemLink {
    tx: mpsc::Sender<Vec<u8>>,
}
impl ModemLink {
    #[allow(clippy::unused_async)]
    async fn recv(&mut self) -> Result<Vec<u8>> {
        Ok(vec![])
    }
    async fn send<T: Into<Vec<u8>>>(
        &mut self,
        data: T,
    ) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.tx.send(data.into()).await
    }
}

struct Modem {
    portr: tokio::io::ReadHalf<PortType>,
    portw: tokio::io::WriteHalf<PortType>,
    to_tx: mpsc::Receiver<Vec<u8>>,
    distribute: Vec<mpsc::Sender<agw::Packet>>,
}

impl Modem {
    #[must_use]
    fn new(port: PortType) -> (Self, ModemLink) {
        let (portr, portw) = tokio::io::split(port);
        let (tx, to_tx) = mpsc::channel(10); // TODO: magic number.
        (
            Self {
                portr,
                portw,
                to_tx,
                distribute: vec![],
            },
            ModemLink { tx },
        )
    }
    async fn run(&mut self) -> Result<()> {
        const MAX_BUF: usize = 8192; // TODO: magic value.
        let mut buf = [0u8; 1024];
        let mut to_modem = Vec::new();
        loop {
            // TODO: if there are bytes to write, have a deadline.
            tokio::select! {
                n = self.portw.write(&to_modem), if !to_modem.is_empty() => {
                    let n = n?;
                    to_modem.drain(..n);
                }
                packet = self.to_tx.recv() => {
                    match packet {
                        Some(packet) => {
                            to_modem.extend(&packet);
                        }
                        None => break
                    }
                }
                // TODO: read whole packets.
                n = self.portr.read(&mut buf), if to_modem.len()<MAX_BUF => {
                    let n = n?;
                    to_modem.extend(&buf[..n]);
                    for _ in &self.distribute {
                    }
                }
            }
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    stderrlog::new()
        .module(module_path!())
        .module("agw")
        .quiet(false)
        .show_module_names(true)
        .verbosity(opt.log_level as usize)
        .timestamp(stderrlog::Timestamp::Second)
        .init()
        .unwrap();
    info!("Starting up");

    // Connect to modem.
    let mut port = if let Some(dev) = opt.dev {
        PortType::Serial(tokio_serial::new(dev.to_str().unwrap(), opt.baud).open_native_async()?)
    } else if let Some(kiss) = opt.kiss {
        PortType::Tcp(tokio::net::TcpStream::connect(kiss).await?)
    } else {
        panic!()
    };

    // Test code to see that we can write to modem.
    if false {
        let packet = rax25::Packet::ui(
            rax25::Addr::new("M0THC-1")?,
            rax25::Addr::new("M0THC-2")?,
            b"hello world in the world",
        );
        let serial = rax25::escape(&packet.serialize(false));
        port.write_all(&serial).await?;
        port.flush().await?;
    }

    let (mut modem, link) = Modem::new(port);
    let listener = tokio::net::TcpListener::bind(&opt.listen).await?;
    tokio::spawn(async move { modem.run().await });
    loop {
        let (stream, peer) = listener.accept().await?;
        let stream = AGWServer::new(stream);
        info!("{peer}: Connected");
        // TODO: register the modem link with the modem.
        let link = link.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, link).await {
                warn!("Client task failed: {e:?}");
            }
        });
    }
}
