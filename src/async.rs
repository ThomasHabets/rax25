//! Async API.
//!
//! This is probably going to be the best API to use.
//!
//! There's currently no background task, so you'll want to have a `read()`
//! outstanding most of the time. Otherwise events like timers and received
//! packets don't happen.
//!
//! If the caller is not interested in the received data, then it's probably
//! best to spawn a task that reads in a loop and discards.
//!
//! # Examples
//!
//! ## Client
//!
//! ```no_run
//! use tokio_serial::SerialPortBuilderExt;
//!
//! use rax25::r#async::{ConnectionBuilder, PortType};
//! use rax25::Addr;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let port = PortType::Serial(tokio_serial::new("/dev/rfcomm0", 9600).open_native_async()?);
//!     let mut client = ConnectionBuilder::new(Addr::new("M0THC-1")?, port)?
//!         .extended(Some(true))
//!         .capture("foo.cap".into())
//!         .connect(Addr::new("M0THC-2")?)
//!         .await?;
//!     client.write(b"Client says hello!").await?;
//!     println!("Got: {:?}", client.read().await?);
//!     Ok(())
//! }
//! ```
//!
//! ## Server
//!
//! ```no_run
//! use tokio_serial::SerialPortBuilderExt;
//!
//! use rax25::r#async::{ConnectionBuilder, PortType};
//! use rax25::Addr;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let port = PortType::Serial(tokio_serial::new("/dev/rfcomm0", 9600).open_native_async()?);
//!     let mut client = ConnectionBuilder::new(Addr::new("M0THC-2")?, port)?
//!         .accept()
//!         .await?;
//!     client.write(b"Server says hello!\n").await?;
//!     println!("Got: {:?}", client.read().await?);
//!     Ok(())
//! }
//! ```
use std::collections::VecDeque;
use std::pin::Pin;

use crate::pcap::PcapWriter;
use crate::state::{self, Event, ReturnEvent};
use crate::{Addr, Packet, PacketType};

use anyhow::{Error, Result};
use log::debug;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

pub enum PortType {
    Serial(tokio_serial::SerialStream),
    Tcp(tokio::net::TcpStream),
}

impl tokio::io::AsyncRead for PortType {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match *self {
            PortType::Serial(ref mut x) => Pin::new(x).poll_read(cx, buf),
            PortType::Tcp(ref mut x) => Pin::new(x).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for PortType {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match *self {
            PortType::Serial(ref mut x) => Pin::new(x).poll_write(cx, buf),
            PortType::Tcp(ref mut x) => Pin::new(x).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match *self {
            PortType::Serial(ref mut x) => Pin::new(x).poll_flush(cx),
            PortType::Tcp(ref mut x) => Pin::new(x).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match *self {
            PortType::Serial(ref mut x) => Pin::new(x).poll_shutdown(cx),
            PortType::Tcp(ref mut x) => Pin::new(x).poll_shutdown(cx),
        }
    }
}

/// Connection Builder.
///
/// A builder for setting up a connection.
pub struct ConnectionBuilder {
    me: Addr,
    extended: Option<bool>,
    capture: Option<std::path::PathBuf>,
    port: PortType,
    t3v: Option<std::time::Duration>,
    srt: Option<std::time::Duration>,
    mtu: Option<usize>,
}

impl ConnectionBuilder {
    /// Create a new builder.
    pub fn new(me: Addr, port: PortType) -> Result<Self> {
        Ok(Self {
            me,
            extended: None,
            capture: None,
            t3v: None,
            srt: None,
            mtu: None,
            port,
        })
    }

    /// Set or prevent extended mode.
    ///
    /// Extended mode allows for more outstanding packets, and thus fewer pauses
    /// for ACK (RR) roundtrips, but is not supported by all implementations.
    ///
    /// Enable or disable extended mode with `Some(bool)`, or use `None` to have
    /// clients first try one, then the other.
    ///
    /// TODO: Heuristics is not actually implemented, so passing None currently
    /// forces extended mode to be off, since that's more supported.
    #[must_use]
    pub fn extended(mut self, ext: Option<bool>) -> ConnectionBuilder {
        self.extended = ext;
        self
    }

    /// Capture incoming and outgoing frames to a pcap file.
    ///
    /// The file must now exist. Failure to create a new file is an error.
    #[must_use]
    pub fn capture(mut self, path: std::path::PathBuf) -> ConnectionBuilder {
        self.capture = Some(path);
        self
    }

    /// Set default SRT value, used for T1 (retransmit) timer.
    #[must_use]
    pub fn srt_default(mut self, v: std::time::Duration) -> ConnectionBuilder {
        self.srt = Some(v);
        self
    }

    /// Set T3 / idle timer.
    #[must_use]
    pub fn t3v(mut self, v: std::time::Duration) -> ConnectionBuilder {
        self.t3v = Some(v);
        self
    }

    /// Set MTU. Only used for outgoing packets.
    #[must_use]
    pub fn mtu(mut self, v: usize) -> ConnectionBuilder {
        self.mtu = Some(v);
        self
    }

    #[must_use]
    fn create_data(&self) -> state::Data {
        let mut data = state::Data::new(self.me.clone());
        if let Some(v) = self.srt {
            data.srt_default(v);
        }
        if let Some(v) = self.t3v {
            data.t3v(v);
        }
        if let Some(v) = self.mtu {
            data.mtu(v);
        }
        data
    }

    /// Initiate a connection.
    pub async fn connect(self, peer: Addr) -> Result<Client> {
        let mut cli = Client::internal_new(self.create_data(), self.port);
        if let Some(capture) = self.capture {
            cli.capture(capture)?;
        }
        // TODO: rather than default to false, we should support trying extended
        // first, then standard.
        cli.connect(peer, self.extended.unwrap_or(false)).await
    }

    /// Accept a single connection.
    ///
    /// For production services this is probably not what you want, since a
    /// server tends to want to serve more than one connection both sequentially
    /// and concurrently.
    ///
    /// But this crate doesn't yet have a multi-connection API. Maybe it
    /// shouldn't, though, but instead rely on a TCP-based multiplexer?
    pub async fn accept(self) -> Result<Client> {
        let mut data = self.create_data();
        data.able_to_establish = true;
        let mut cli = Client::internal_new(data, self.port);
        // Extended attribute ignored. Should it be?
        if let Some(capture) = self.capture {
            cli.capture(capture)?;
        }
        loop {
            cli.wait_event().await?;
            if cli.state.is_state_connected() {
                return Ok(cli);
            }
        }
    }
}

/// An async AX.25 client.
///
/// Despite its name, it's used both for the initiating and listening side of a
/// connection. Probably should be renamed.
pub struct Client {
    state: Box<dyn state::State>,
    data: state::Data,
    port: PortType,
    eof: bool,
    incoming: VecDeque<u8>,
    incoming_kiss: VecDeque<u8>,
    incoming_frames: VecDeque<Packet>,

    pcap: Option<PcapWriter>,
}

/// Turn bytes into frames.
///
/// Given an input buffer `ibuf` of KISS data, drain all packets we can find.
#[must_use]
fn kisser_read(ibuf: &mut VecDeque<u8>, ext: Option<bool>) -> Vec<Packet> {
    let mut ret = Vec::new();
    while let Some((a, b)) = crate::find_frame(ibuf) {
        if b - a < 14 {
            ibuf.drain(..(a + 1));
            continue;
        }
        let pb: Vec<_> = ibuf.iter().skip(a + 2).take(b - a - 2).cloned().collect();
        ibuf.drain(..b);
        let pb = crate::unescape(&pb);
        match Packet::parse(&pb, ext) {
            Ok(packet) => {
                debug!("parsed {packet:?}");
                ret.push(packet);
            }
            Err(e) => {
                debug!("Failed to parse packet: {e:?}");
            }
        }
    }
    ret
}

impl Client {
    // TODO: now that we have a builder, these functions should be cleaned up.
    #[must_use]
    fn internal_new(data: state::Data, port: PortType) -> Self {
        Self {
            eof: false,
            incoming: VecDeque::new(),
            incoming_frames: VecDeque::new(),
            incoming_kiss: VecDeque::new(),
            port,
            state: state::new(),
            data,
            pcap: None,
        }
    }

    /// Initiate a connection.
    async fn connect(mut self, peer: Addr, ext: bool) -> Result<Self> {
        self.actions(Event::Connect { addr: peer, ext }).await?;
        loop {
            self.wait_event().await?;
            debug!("State after waiting: {}", self.state.name());
            if self.state.is_state_connected() {
                return Ok(self);
            }
            if self.state.is_state_disconnected() {
                return Err(Error::msg("connection timed out"));
            }
        }
    }
    fn capture(&mut self, filename: std::path::PathBuf) -> Result<()> {
        let pcap = PcapWriter::create(filename)?;
        self.pcap = Some(pcap);
        Ok(())
    }
    fn extract_packets(&mut self) {
        self.incoming_frames
            .extend(kisser_read(&mut self.incoming_kiss, Some(self.data.ext())));
    }

    /// Wait for an event, and handle it.
    ///
    /// If there's a chance that the caller is interested, then return. If the
    /// caller wants to wait more, they can call again.
    async fn wait_event(&mut self) -> Result<()> {
        let mut buf = [0; 1024];

        let state_name = self.state.name();
        // First process all incoming frames. This is non-blocking.
        while let Some(p) = self.incoming_frames.pop_front() {
            debug!("processing packet {:?}", p.packet_type);
            if let Some(f) = &mut self.pcap {
                f.write(&p.serialize(self.data.ext()))?;
            }
            self.actions_packet(&p).await?;
            debug!(
                "post packet: {} {:?} {:?}",
                self.state.name(),
                self.data.t1.remaining(),
                self.data.t3.remaining()
            );
        }

        // wait_event is called when connecting, accepting, or attempting to
        // read. In the first two cases there's no incoming bytes. In the
        // last case we actually want to return the bytes ASAP. So we do that
        // here, without waiting for timers, more packets, or more serial
        // bytes.
        if !self.incoming.is_empty() {
            return Ok(());
        }

        // If the state changed, there's a good chance that the client wants to
        // know.
        if self.state.name() != state_name {
            return Ok(());
        }

        let (t1, t3) = self.timer_13();
        tokio::pin!(t1);
        tokio::pin!(t3);

        tokio::select! {
            () = &mut t1 => {
                debug!("async con event: T1");
                self.actions(Event::T1).await?;
            },
            () = &mut t3 => {
                debug!("async con event: T3");
                self.actions(Event::T3).await?
            },
            res = self.port.read(&mut buf) => match res {
            Ok(n) => {
                debug!("Read {n} bytes from serial port");
                let buf = &buf[..n];
                self.incoming_kiss.extend(buf);
                self.extract_packets();
            },
            Err(e) => eprintln!("Error reading from serial port: {e:?}"),
            },
        }
        debug!(
            "async con post state: {} {:?} {:?}",
            self.state.name(),
            self.data.t1.remaining(),
            self.data.t3.remaining()
        );
        Ok(())
    }
    async fn actions_packet(&mut self, packet: &Packet) -> Result<()> {
        match &packet.packet_type {
            PacketType::Sabm(p) => self.actions(state::Event::Sabm(p.clone(), packet.src.clone())),
            PacketType::Sabme(p) => {
                self.actions(state::Event::Sabme(p.clone(), packet.src.clone()))
            }
            PacketType::Ua(ua) => self.actions(state::Event::Ua(ua.clone())),
            PacketType::Disc(p) => self.actions(state::Event::Disc(p.clone())),
            PacketType::Rnr(p) => self.actions(state::Event::Rnr(p.clone())),
            PacketType::Rej(p) => self.actions(state::Event::Rej(p.clone())),
            PacketType::Srej(p) => self.actions(state::Event::Srej(p.clone())),
            PacketType::Frmr(p) => self.actions(state::Event::Frmr(p.clone())),
            PacketType::Xid(p) => {
                self.actions(state::Event::Xid(p.clone(), packet.command_response))
            }
            PacketType::Ui(p) => self.actions(state::Event::Ui(p.clone(), packet.command_response)),
            PacketType::Test(p) => {
                self.actions(state::Event::Test(p.clone(), packet.command_response))
            }
            PacketType::Dm(p) => self.actions(state::Event::Dm(p.clone())),
            PacketType::Rr(rr) => {
                self.actions(state::Event::Rr(rr.clone(), packet.command_response))
            }
            PacketType::Iframe(iframe) => self.actions(state::Event::Iframe(
                iframe.clone(),
                packet.command_response,
            )),
        }
        .await
    }

    /// Disconnect an established connection.
    ///
    /// This currently does not wait for the UA response.
    pub async fn disconnect(mut self) -> Result<()> {
        // TODO: wait for the UA
        self.actions(Event::Disconnect).await
    }

    fn sync_disconnect(&mut self) {
        if !self.state.is_state_disconnected() {
            eprintln!("TODO: sync_disconnect")
        }
    }

    /// Write data on an established connection.
    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        self.actions(Event::Data(data.to_vec())).await
    }

    /// Get a pair of sleepers from the T1/T3 timers.
    ///
    /// TODO: 24h is used as "forever". Use something better?
    fn timer_13(&self) -> (tokio::time::Sleep, tokio::time::Sleep) {
        let timer1 = tokio::time::sleep(
            self.data
                .t1
                .remaining()
                .unwrap_or(std::time::Duration::from_secs(86400)),
        );
        let timer3 = tokio::time::sleep(
            self.data
                .t3
                .remaining()
                .unwrap_or(std::time::Duration::from_secs(86400)),
        );
        (timer1, timer3)
    }

    /// Read from the established connection.
    ///
    /// This function must be called to keep the state machine running.
    /// Otherwise timers and incoming packets are not processed.
    ///
    /// If the caller intends to not call read() for a long time, then it should
    /// spawn a task that does it anyway, and handle any read data on its own
    /// side.
    pub async fn read(&mut self) -> Result<Vec<u8>> {
        loop {
            self.wait_event().await?;
            if self.incoming.is_empty() && self.eof {
                return Ok(vec![]);
            }
            if !self.incoming.is_empty() {
                let ret: Vec<_> = self.incoming.iter().cloned().collect();
                self.incoming.clear();
                return Ok(ret);
            }
        }
    }

    async fn actions(&mut self, event: Event) -> Result<()> {
        let (state, actions) = state::handle(&*self.state, &mut self.data, &event);
        if let Some(state) = state {
            let _ = std::mem::replace(&mut self.state, state);
        }
        for act in actions {
            match &act {
                ReturnEvent::DlError(e) => eprintln!("DLError: {e:?}"),
                ReturnEvent::Data(res) => match res {
                    state::Res::None => {}
                    state::Res::EOF => self.eof = true,
                    state::Res::Some(d) => self.incoming.extend(d),
                },
                _ => {
                    // println!("Do action: {act:?}");
                }
            }
            if let Some(frame) = act.serialize(self.data.ext()) {
                if let Some(f) = &mut self.pcap {
                    f.write(&frame)?;
                }
                let frame = crate::escape(&frame);
                self.port.write_all(&frame).await?;
                self.port.flush().await?;
            }
        }
        Ok(())
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.sync_disconnect()
    }
}
/* vim: textwidth=80
 */
