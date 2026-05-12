//! AGW server.

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
    // TODO: also support TCP.
    #[arg(long, short)]
    dev: std::path::PathBuf,

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
    port: PortType,
    to_tx: mpsc::Receiver<Vec<u8>>,
    distribute: Vec<mpsc::Sender<agw::Packet>>,
}

impl Modem {
    #[must_use]
    fn new(port: PortType) -> (Self, ModemLink) {
        let (tx, to_tx) = mpsc::channel(10); // TODO: magic number.
        (
            Self {
                port,
                to_tx,
                distribute: vec![],
            },
            ModemLink { tx },
        )
    }
    async fn run(&mut self) -> Result<()> {
        let mut buf = [0u8; 1024];
        loop {
            tokio::select! {
                packet = self.to_tx.recv() => {
                    match packet {
                        Some(packet) => {
                            self.port.write_all(&packet).await?;
                        }
                        None => break
                    }
                }
                // TODO: read whole packets.
                n = self.port.read(&mut buf) => {
                    let _n = n?;
                    //let _buf = &buf[..n];
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
        .verbosity(opt.log_level as usize)
        .timestamp(stderrlog::Timestamp::Second)
        .init()
        .unwrap();
    info!("Starting up");
    let port = PortType::Serial(
        tokio_serial::new(opt.dev.to_str().unwrap(), opt.baud).open_native_async()?,
    );
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
