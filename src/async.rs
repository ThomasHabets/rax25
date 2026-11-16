//! Async API.
//!
//! This is probably going to be the best API to use.
//!
//! Established clients run protocol I/O and timers in a background task.
//! Reads are cancellation-safe channel receives; they need not remain pending
//! for acknowledgements and retransmissions to progress. Receive buffering is
//! bounded: a client that does not consume incoming data can be disconnected.
//!
//! # Examples
//!
//! ## Client
//!
//! ```no_run
//! use rax25::r#async::{connect_kiss_endpoint, ConnectionBuilder};
//! use rax25::Callsign;
//!
//! #[tokio::main]
//! async fn main() -> rax25::Result<()> {
//!     let port = connect_kiss_endpoint("serial:///dev/rfcomm0").await?;
//!     let mut client = ConnectionBuilder::new(Callsign::new("M0THC-1")?, port)?
//!         .extended(Some(true))
//!         .capture("foo.cap".into())
//!         .connect(Callsign::new("M0THC-2")?)
//!         .await?;
//!     client.write(b"Client says hello!").await?.await?;
//!     println!("Got: {:?}", client.read().await?);
//!     Ok(())
//! }
//! ```
//!
//! ## Server
//!
//! ```no_run
//! use rax25::r#async::{connect_kiss_endpoint, ConnectionBuilder};
//! use rax25::Callsign;
//!
//! #[tokio::main]
//! async fn main() -> rax25::Result<()> {
//!     let port = connect_kiss_endpoint("serial:///dev/rfcomm0").await?;
//!     let mut client = ConnectionBuilder::new(Callsign::new("M0THC-2")?, port)?
//!         .accept()
//!         .await?;
//!     client.write(b"Server says hello!\n").await?.await?;
//!     println!("Got: {:?}", client.read().await?);
//!     Ok(())
//! }
//! ```
use std::collections::{HashSet, VecDeque};
use std::pin::Pin;

use crate::pcap::PcapWriter;
use crate::state::{self, Event, NegotiatedParameters, ReturnEvent, XidConfig};
use crate::{Callsign, Error, Experiment, Packet, PacketType, Result};

use log::{debug, error, trace, warn};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio_serial::SerialPortBuilderExt;

pub enum PortType {
    Serial(tokio_serial::SerialStream),
    Tcp(tokio::net::TcpStream),
}

#[allow(clippy::doc_markdown)]
/// Connect to a KISS endpoint.
///
/// Supported endpoint formats are `serial:///dev/rfcomm0` and
/// `tcp://localhost:8000`.
pub async fn connect_kiss_endpoint(endpoint: &str) -> Result<PortType> {
    if let Some(addr) = endpoint.strip_prefix("tcp://") {
        if addr.is_empty() {
            return Err(Error::InvalidEndpoint {
                endpoint: endpoint.to_owned(),
                reason: "empty TCP KISS endpoint",
            });
        }
        return Ok(PortType::Tcp(
            tokio::net::TcpStream::connect(addr)
                .await
                .map_err(|source| Error::Endpoint {
                    endpoint: endpoint.to_owned(),
                    source,
                })?,
        ));
    }

    if let Some(path) = endpoint.strip_prefix("serial://") {
        if path.is_empty() {
            return Err(Error::InvalidEndpoint {
                endpoint: endpoint.to_owned(),
                reason: "empty serial KISS endpoint",
            });
        }
        return Ok(PortType::Serial(
            tokio_serial::new(path, 9600)
                .open_native_async()
                .map_err(|source| Error::SerialEndpoint {
                    endpoint: endpoint.to_owned(),
                    source,
                })?,
        ));
    }

    Err(Error::InvalidEndpoint {
        endpoint: endpoint.to_owned(),
        reason: "KISS endpoint must start with tcp:// or serial://",
    })
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
    me: Callsign,
    extended: Option<bool>,
    capture: Option<std::path::PathBuf>,
    port: PortType,
    t3v: Option<std::time::Duration>,
    srt: Option<std::time::Duration>,
    mtu: Option<usize>,
    experiments: HashSet<Experiment>,
    xid: Option<XidConfig>,
}

impl ConnectionBuilder {
    /// Create a new builder.
    pub fn new(me: Callsign, port: PortType) -> Result<Self> {
        Ok(Self {
            me,
            extended: None,
            capture: None,
            t3v: None,
            srt: None,
            mtu: None,
            port,
            experiments: HashSet::new(),
            xid: None,
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
    /// With XID enabled, `None` prefers extended mode and permits standard
    /// fallback. Without XID, `None` selects standard mode.
    #[must_use]
    pub fn extended(mut self, ext: Option<bool>) -> ConnectionBuilder {
        self.extended = ext;
        self
    }

    /// Enable XID parameter negotiation before establishing the link.
    #[must_use]
    pub fn xid(mut self, config: XidConfig) -> ConnectionBuilder {
        self.xid = Some(config);
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

    /// Enable experiments.
    #[must_use]
    pub fn with_experiments<I, E>(mut self, ex: I) -> ConnectionBuilder
    where
        I: IntoIterator<Item = E>,
        E: std::borrow::Borrow<Experiment>,
    {
        self.enable_experiments(ex);
        self
    }

    /// Enable experiments.
    pub fn enable_experiments<I, E>(&mut self, ex: I)
    where
        I: IntoIterator<Item = E>,
        E: std::borrow::Borrow<Experiment>,
    {
        self.experiments.extend(ex.into_iter().map(|e| *e.borrow()));
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
        data.experiments.clone_from(&self.experiments);
        if let Some(config) = &self.xid {
            data.set_xid_config(config.clone());
        }
        if let Some(v) = self.srt {
            data.srt_default(v);
        }
        if let Some(v) = self.t3v {
            data.t3v(v);
        }
        if let Some(v) = self.mtu {
            data.mtu(v);
        }
        data.enable_experiments(&self.experiments);
        data
    }

    /// Initiate a connection.
    ///
    /// # Cancellation Safety
    /// Not cancellation-safe: cancelling drops the owned modem connection and
    /// protocol state without completing a disconnect. XID or SABM(E) may
    /// already have been sent, or a KISS frame may have been partially written.
    /// The peer may retain a pending or established link until it times out.
    pub async fn connect(self, peer: Callsign) -> Result<Client> {
        if let Some(config) = &self.xid {
            config.validate()?;
        }
        let extended = self.extended;
        let xid = self.xid.is_some();
        let mut cli = Driver::internal_new(
            self.create_data(),
            self.port,
            self.extended.unwrap_or(false),
        );
        if let Some(capture) = self.capture {
            cli.capture(capture)?;
        }
        Ok(Client::spawn(cli.connect(peer, xid, extended).await?))
    }

    /// Accept a single connection.
    ///
    /// For production services this is probably not what you want, since a
    /// server tends to want to serve more than one connection both sequentially
    /// and concurrently.
    ///
    /// But this crate doesn't yet have a multi-connection API. Maybe it
    /// shouldn't, though, but instead rely on a TCP-based multiplexer?
    ///
    /// # Cancellation Safety
    /// Not cancellation-safe: cancelling drops the owned modem and protocol
    /// state. A handshake response may already have been sent or partially
    /// written, leaving the peer connected without a local client. No graceful
    /// disconnect is performed when the future is dropped.
    pub async fn accept(self) -> Result<Client> {
        if let Some(config) = &self.xid {
            config.validate()?;
        }
        let mut data = self.create_data();
        data.able_to_establish = true;

        // Default to assuming not extended. It doesn't affect parsing of
        // SABM(E), and we set it later it it does end up being extended.
        let mut cli = Driver::internal_new(data, self.port, false);
        // Extended attribute ignored. Should it be?
        if let Some(capture) = self.capture {
            cli.capture(capture)?;
        }
        debug!("rax25: Awaiting incoming SABM");
        loop {
            cli.wait_event().await?;
            if cli.state.is_state_connected() {
                return Ok(Client::spawn(cli));
            }
        }
    }
}

/// A parser & writer of kiss packets directly to a port.
///
/// Every connection will have one, since extended and standard mode packets
/// parse differently.
struct KissPort {
    outgoing: KissWrites,
    /// Incoming raw bytes.
    incoming_kiss: VecDeque<u8>,

    /// Pending packets in need of processing.
    incoming_frames: VecDeque<Packet>,

    /// Parse as extended mode.
    ext: bool,

    /// Modem port.
    /// This is a temporary state since the current implementation hogs the
    /// whole serial port.
    port: PortType,
}

impl KissPort {
    async fn process(&mut self, mut pcap: Option<&mut PcapWriter>) -> Result<()> {
        let mut buf = [0; 1024];
        loop {
            match self.port.read(&mut buf).await {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "EOF from KISS port",
                    )
                    .into());
                }
                Ok(n) => {
                    trace!("Read {n} bytes from serial port");
                    let buf = &buf[..n];
                    self.incoming_kiss.extend(buf);
                    self.extract_packets(pcap.as_deref_mut());
                    if !self.incoming_frames.is_empty() {
                        return Ok(());
                    }
                }
                // TODO: if KISS is TCP, we should try reconnecting.
                Err(e) => return Err(e.into()),
            }
        }
    }
    #[must_use]
    fn len(&self) -> usize {
        self.incoming_frames.len()
    }
    #[must_use]
    fn pop_frame(&mut self) -> Option<Packet> {
        self.incoming_frames.pop_front()
    }

    fn extract_packets(&mut self, pcap: Option<&mut PcapWriter>) {
        self.incoming_frames
            .extend(kisser_read(&mut self.incoming_kiss, Some(self.ext), pcap));
    }
    // Queued bytes and progress survive cancellation while this port survives.
    async fn write(&mut self, packet: &Packet, linux_extended_hint: bool) -> Result<()> {
        let bytes = packet.serialize_with_linux_extended_hint(linux_extended_hint);
        self.outgoing.write(&mut self.port, &bytes).await
    }
}

/// Pending KISS writes live outside the futures driving them.
#[derive(Default)]
pub(crate) struct KissWrites {
    frames: VecDeque<Vec<u8>>,
    offset: usize,
}

impl KissWrites {
    pub(crate) async fn write(
        &mut self,
        port: &mut (impl AsyncWrite + Unpin),
        bytes: &[u8],
    ) -> Result<()> {
        self.frames.push_back(crate::escape(bytes));
        self.flush(port).await
    }

    pub(crate) async fn flush(&mut self, port: &mut (impl AsyncWrite + Unpin)) -> Result<()> {
        while let Some(frame) = self.frames.front() {
            while self.offset < frame.len() {
                let count = port.write(&frame[self.offset..]).await?;
                if count == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
                }
                self.offset += count;
            }
            self.frames.pop_front();
            self.offset = 0;
        }
        port.flush().await?;
        Ok(())
    }
}

/// Protocol state owned by connection setup, then by the background task.
struct Driver {
    state: Box<dyn state::State>,
    data: state::Data,
    eof: bool,

    /// Incoming payload bytes ready to be delivered to the application.
    incoming: VecDeque<u8>,
    kissport: KissPort,

    pcap: Option<PcapWriter>,
}

enum ClientCommand {
    Write(Vec<u8>, tokio::sync::oneshot::Sender<()>),
    Disconnect(tokio::sync::oneshot::Sender<Result<()>>),
}

/// Optional notification that a queued write was processed by the local task.
/// This does not confirm remote acknowledgement or application delivery.
/// Dropping this handle does not cancel or resubmit the queued write. Retain
/// and poll the same handle to resume waiting after a timeout.
pub struct WriteCompletion(tokio::sync::oneshot::Receiver<()>);

impl std::future::Future for WriteCompletion {
    type Output = Result<()>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map(|result| {
            result.map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe).into())
        })
    }
}

/// An established async AX.25 link with independently driven I/O and timers.
/// Dropping the client requests a best-effort disconnect in its background task.
pub struct Client {
    /// Bounded requests to the protocol task. Dropping this sender requests
    /// best-effort disconnect once previously queued commands are processed.
    commands: tokio::sync::mpsc::Sender<ClientCommand>,
    /// Bounded application-data queue. Receives are cancellation-safe; channel
    /// closure means buffered data is exhausted and the task result is ready.
    received: tokio::sync::mpsc::Receiver<Vec<u8>>,
    /// Task completion result, published before the receive channel closes.
    /// None while running (or after an error is consumed); clean EOF is retained
    /// so subsequent reads and disconnect requests continue to succeed.
    task_result: std::sync::Arc<std::sync::Mutex<Option<Result<()>>>>,
    /// Snapshot of parameters negotiated during establishment, available without
    /// querying the task. None if the link was established without XID agreement.
    negotiated: Option<NegotiatedParameters>,
}

impl Client {
    fn spawn(driver: Driver) -> Self {
        let (commands, rx) = tokio::sync::mpsc::channel(32);
        let (tx, received) = tokio::sync::mpsc::channel(128);
        let task_result = std::sync::Arc::new(std::sync::Mutex::new(None));
        let status = task_result.clone();
        let negotiated = driver.data.negotiated_parameters().cloned();
        tokio::spawn(async move {
            let result = driver.run(rx, &tx).await;
            *status
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result);
            // Close only after publishing the task result, so readers
            // drain data before receiving the original I/O/protocol error.
            drop(tx);
        });
        Self {
            commands,
            received,
            task_result,
            negotiated,
        }
    }

    /// Receive application data, or an empty vector after a clean disconnect.
    /// Protocol I/O and timers progress independently of reads.
    ///
    /// # Cancellation Safety
    /// Cancellation-safe: cancelling a pending receive leaves data queued.
    pub async fn read(&mut self) -> Result<Vec<u8>> {
        if let Some(data) = self.received.recv().await {
            return Ok(data);
        }
        self.check_task_result()?;
        Ok(Vec::new())
    }

    fn check_task_result(&self) -> Result<()> {
        let mut task_result = self
            .task_result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match task_result.take() {
            Some(Ok(())) => {
                *task_result = Some(Ok(()));
                Ok(())
            }
            Some(Err(error)) => Err(error),
            None => {
                warn!(
                    "Further operations called on client that already returned error. Returning BrokenPipe"
                );
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe).into())
            }
        }
    }

    /// Queue application bytes and return an optional completion future.
    /// Await the returned handle to wait for local processing, not remote ACK:
    /// `client.write(bytes).await?.await?`. Drop it to only enqueue the bytes.
    ///
    /// # Cancellation Safety
    /// Cancellation-safe: if this future is cancelled while waiting for queue
    /// capacity, nothing is submitted. There is no suspension between enqueueing
    /// and returning the handle. Once returned, the write proceeds independently
    /// of whether the handle is polled or dropped; do not resubmit those bytes.
    pub async fn write(&mut self, data: &[u8]) -> Result<WriteCompletion> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.commands
            .send(ClientCommand::Write(data.to_vec(), tx))
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
        Ok(WriteCompletion(rx))
    }

    /// Disconnect and wait for release completion.
    ///
    /// # Cancellation Safety
    /// This future owns the client, so cancelling it drops the client, even if
    /// the disconnect command has not yet been enqueued. Dropping the client
    /// closes its command channel; the background task processes any queued
    /// commands, then attempts a best-effort disconnect with a 30-second cleanup
    /// deadline. If the disconnect command was already enqueued, the task
    /// continues that operation normally. Cancellation never aborts the task,
    /// but the caller no longer waits for or observes the disconnect result.
    pub async fn disconnect(self) -> Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self
            .commands
            .send(ClientCommand::Disconnect(tx))
            .await
            .is_err()
        {
            return self.check_task_result();
        }
        rx.await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?
    }

    /// Parameters agreed during establishment, or `None` without negotiation.
    #[must_use]
    pub fn negotiated_parameters(&self) -> Option<&NegotiatedParameters> {
        self.negotiated.as_ref()
    }
}

/// Turn bytes into frames.
///
/// Given an input buffer `ibuf` of KISS data, drain all packets we can find.
#[must_use]
fn kisser_read(
    ibuf: &mut VecDeque<u8>,
    ext: Option<bool>,
    mut pcap: Option<&mut PcapWriter>,
) -> Vec<Packet> {
    let mut ret = Vec::new();
    while let Some((a, b)) = crate::find_frame(ibuf) {
        if b - a < 14 {
            ibuf.drain(..=a);
            continue;
        }
        let pb: Vec<_> = ibuf.iter().skip(a + 2).take(b - a - 2).copied().collect();
        ibuf.drain(..b);
        let pb = match crate::unescape(&pb) {
            Ok(bytes) => bytes,
            Err(error) => {
                debug!("Discarding malformed KISS frame: {error}");
                continue;
            }
        };
        match Packet::parse(&pb, ext) {
            Ok(packet) => {
                trace!("rax25: parsed {packet:?}");
                //let mut ext = ext.unwrap_or(false);
                if let PacketType::Sabme(_) = packet.packet_type {
                    //ext = true;
                }
                if false {
                    // TODO: make serialization perfect. It's not obvious what
                    // perfect is, since we may want to both preserve the extra
                    // bits in the address fields *and* use them to signify
                    // extended mode.
                    trace!(
                        "BYTES: {:?}",
                        Packet::parse(&packet.serialize_with_linux_extended_hint(true), ext)
                    );
                    assert_eq!(&packet.serialize_with_linux_extended_hint(true), &pb);
                }
                if let Some(f) = &mut pcap
                    && let Err(e) = f.write(&pb)
                {
                    error!("Failed to write to pcap: {e}");
                }
                ret.push(packet);
            }
            Err(e) => {
                debug!("rax25: Failed to parse packet: {e:?}");
            }
        }
    }
    ret
}

impl Driver {
    async fn run(
        mut self,
        mut commands: tokio::sync::mpsc::Receiver<ClientCommand>,
        received: &tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> Result<()> {
        loop {
            self.process_frames().await?;
            if !self.incoming.is_empty() {
                let bytes = self.incoming.drain(..).collect();
                if received.try_send(bytes).is_err() {
                    // Never wait on a full application queue while protocol
                    // timers and acknowledgements need servicing.
                    let _ =
                        tokio::time::timeout(std::time::Duration::from_secs(30), self.disconnect())
                            .await;
                    return Err(Error::QueueFull);
                }
            }
            if self.eof || self.state.is_state_disconnected() {
                return Ok(());
            }
            let command = tokio::select! {
                command = commands.recv() => command,
                event = self.next_event() => {
                    if let Some(event) = event? {
                        self.actions(event).await?;
                    }
                    continue;
                }
            };
            match command {
                Some(ClientCommand::Write(bytes, reply)) => {
                    self.actions(Event::Data(bytes)).await?;
                    let _ = reply.send(());
                }
                Some(ClientCommand::Disconnect(reply)) => {
                    let result = self.disconnect().await;
                    let _ = reply.send(result);
                    return Ok(());
                }
                // Client was dropped. Implicit disconnect.
                None => {
                    return tokio::time::timeout(
                        std::time::Duration::from_secs(30),
                        self.disconnect(),
                    )
                    .await?;
                }
            }
        }
    }
    // TODO: now that we have a builder, these functions should be cleaned up.
    #[must_use]
    fn internal_new(data: state::Data, port: PortType, ext: bool) -> Self {
        Self {
            eof: false,
            incoming: VecDeque::new(),
            kissport: KissPort {
                outgoing: KissWrites::default(),
                port,
                incoming_kiss: VecDeque::new(),
                incoming_frames: VecDeque::new(),
                ext,
            },
            state: state::new(),
            data,
            pcap: None,
        }
    }

    /// Initiate a connection.
    /// Not cancellation-safe: owns the client and can be interrupted during
    /// `actions` or `wait_event`, dropping the modem without graceful release.
    async fn connect(mut self, peer: Callsign, xid: bool, ext: Option<bool>) -> Result<Self> {
        let event = if xid {
            Event::ConnectWithXid { addr: peer, ext }
        } else {
            Event::Connect {
                addr: peer,
                ext: self.kissport.ext,
            }
        };
        self.actions(event).await?;
        loop {
            self.wait_event().await?;
            trace!("rax25: State after waiting: {}", self.state.name());
            if self.state.is_state_connected() {
                return Ok(self);
            }
            if self.state.is_state_disconnected() {
                return Err(Error::ConnectionTimeout);
            }
        }
    }
    fn capture(&mut self, filename: std::path::PathBuf) -> Result<()> {
        let pcap = PcapWriter::create(filename)?;
        self.pcap = Some(pcap);
        Ok(())
    }

    /// Wait for an event, and handle it.
    ///
    /// If there's a chance that the caller is interested, then return. If the
    /// caller wants to wait more, they can call again.
    ///
    /// Not cancellation-safe: a frame is removed from the receive queue before
    /// `actions_packet` awaits writes. Timer handling also invokes actions; its
    /// state changes and uncompleted actions cannot be rolled back or resumed.
    async fn wait_event(&mut self) -> Result<()> {
        self.kissport
            .outgoing
            .flush(&mut self.kissport.port)
            .await?;
        trace!(
            "rax25: Waiting for event. {} packets ready",
            self.kissport.len()
        );
        let state_name = self.state.name();
        self.process_frames().await?;

        // Return delivered data and state transitions without waiting for I/O.
        if !self.incoming.is_empty() {
            return Ok(());
        }
        if self.state.name() != state_name {
            return Ok(());
        }

        let event = self.next_event().await?;
        if let Some(event) = event {
            self.actions(event).await?;
        }
        Ok(())
    }

    // Called outside select branches so frame actions always finish.
    async fn process_frames(&mut self) -> Result<()> {
        while let Some(p) = self.kissport.pop_frame() {
            if p.dst.callsign() != &self.data.me {
                trace!("rax25: Skipping packet not for {:?}", self.data.me.call());
                continue;
            }
            if let Some(peer) = &self.data.peer
                && peer != p.src.callsign()
            {
                trace!(
                    "rax25: Skipping packet not from {peer:?} but {:?}",
                    p.src.call()
                );
                continue;
            }
            trace!("rax25: processing packet {:?}", p.packet_type);
            self.actions_packet(&p).await?;
            trace!(
                "rax25: post packet: {} {:?} {:?}",
                self.state.name(),
                self.data.t1.remaining(),
                self.data.t3.remaining()
            );
        }

        if self.state.is_state_connected() {
            self.kissport.ext = self.data.modulus.is_extended();
        }
        Ok(())
    }

    // Cancellation-safe: only waits for timers or stores bytes/frames in
    // KissPort. Protocol actions are deliberately executed by the caller.
    async fn next_event(&mut self) -> Result<Option<Event>> {
        let (t1, t3) = self.timer_13();
        tokio::pin!(t1);
        tokio::pin!(t3);
        let management = tokio::time::sleep(
            self.data
                .management_remaining()
                .unwrap_or(std::time::Duration::from_hours(24)),
        );
        tokio::pin!(management);

        tokio::select! {
            () = &mut management => {
                return Ok(Some(Event::ManagementTimeout));
            },
            () = &mut t1 => {
                debug!("rax25: async con event: T1");
                return Ok(Some(Event::T1));
            },
            () = &mut t3 => {
                debug!("rax25: async con event: T3");
                return Ok(Some(Event::T3));
            },
            res = self.kissport.process(self.pcap.as_mut()) => {
            if let Err(e) = res {
                warn!("Error reading from serial port: {e:?}");
                return Err(e);
            }
            },
        }
        debug!(
            "rax25: async con post state: {} {:?} {:?}",
            self.state.name(),
            self.data.t1.remaining(),
            self.data.t3.remaining()
        );
        Ok(None)
    }

    /// This function sends packets to the state machine.
    /// Cancellation safety is the same as actions: processing may be committed
    /// before its resulting I/O and data-delivery actions have completed.
    async fn actions_packet(&mut self, packet: &Packet) -> Result<()> {
        self.actions(crate::engine::packet_event(packet)).await
    }

    /// Disconnect an established connection.
    ///
    /// Waits for release completion, subject to retries and modem EOF.
    ///
    /// # Cancellation Safety
    /// Not cancellation-safe: this consumes the client. Cancelling drops the
    /// modem and protocol state, possibly with a partial DISC on the transport
    /// or before its acknowledgement. Drop does not finish the disconnect.
    async fn disconnect(mut self) -> Result<()> {
        trace!("rax25: Disconnecting while in state {}", self.state.name());
        self.actions(Event::Disconnect).await?;
        match self.state.name().as_str() {
            "AwaitingRelease" => loop {
                self.incoming.clear();
                match self.wait_event().await {
                    Ok(()) => {}
                    // If while waiting for UA to our DISC, KISS goes
                    // away, that's fine.
                    //
                    // This will happen during testing if the KISS is
                    // just a lossy bent pipe to the server, and the
                    // server exits after sending UA.
                    //
                    // OK, kind of an edge case, but it's fine.
                    Err(e) if is_error_eof(&e) => return Ok(()),
                    Err(e) => return Err(e),
                }
                if self.state.is_state_disconnected() {
                    // We got out UA.
                    break Ok(());
                }
            },
            "Disconnected" => Ok(()),
            other => {
                trace!("Disconnect request in unexpected state {other}");
                Ok(())
            }
        }
    }

    fn sync_disconnect(&mut self) {
        if !self.state.is_state_disconnected() {
            trace!("TODO: sync_disconnect");
        }
    }

    /// Get a pair of sleepers from the T1/T3 timers.
    ///
    /// TODO: 24h is used as "forever". Use something better?
    fn timer_13(&self) -> (tokio::time::Sleep, tokio::time::Sleep) {
        let timer1 = tokio::time::sleep(
            self.data
                .t1
                .remaining()
                .unwrap_or(std::time::Duration::from_hours(24)),
        );
        let timer3 = tokio::time::sleep(
            self.data
                .t3
                .remaining()
                .unwrap_or(std::time::Duration::from_hours(24)),
        );
        (timer1, timer3)
    }

    /// Update state machine from a new event happening, that is not "a packet
    /// arrived".
    ///
    /// Not cancellation-safe: handle commits state changes synchronously, then
    /// this future owns the resulting action list across packet-write awaits.
    /// Dropping it loses unprocessed actions; queued writes retain progress.
    async fn actions(&mut self, event: Event) -> Result<()> {
        let (state, actions) = state::handle(&*self.state, &mut self.data, &event);
        if let Some(state) = state {
            let _ = std::mem::replace(&mut self.state, state);
        }
        for act in actions {
            match &act {
                ReturnEvent::DlError(e) => warn!("DLError: {e:?}"),
                ReturnEvent::Data(res) => {
                    trace!("rax25: ReturnEvent::Data {act:?}");
                    match res {
                        state::Res::None => {}
                        state::Res::EOF => self.eof = true,
                        state::Res::Some(d) => self.incoming.extend(d),
                    }
                }
                ReturnEvent::Packet(p) => {
                    let linux = self
                        .data
                        .experiments
                        .contains(&Experiment::LinuxExtendedHint);
                    // TODO: we should probably only flip this on SABME, right?
                    self.kissport.ext = self.data.ext();
                    self.kissport.write(p, linux).await?;
                    if let Some(f) = &mut self.pcap {
                        f.write(&p.serialize_with_linux_extended_hint(linux))?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.sync_disconnect();
    }
}

fn is_error_eof(e: &Error) -> bool {
    matches!(e, Error::Io(io_err) if io_err.kind() == std::io::ErrorKind::UnexpectedEof)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn cancelled_kiss_write_resumes_before_next_frame() -> crate::Result<()> {
        use tokio::io::AsyncReadExt;
        let (mut writer, mut reader) = tokio::io::duplex(1);
        let mut pending = super::KissWrites::default();
        let first = [0xc0, 0xdb, 1];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                pending.write(&mut writer, &first),
            )
            .await
            .is_err()
        );
        assert!(pending.offset > 0);
        let receive = tokio::spawn(async move {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await.unwrap();
            bytes
        });
        pending.write(&mut writer, &[2, 3]).await?;
        drop(writer);
        let expected = [crate::escape(&first), crate::escape(&[2, 3])].concat();
        assert_eq!(receive.await.unwrap(), expected);
        Ok(())
    }

    use super::*;

    async fn client_pair() -> Result<(Client, Client)> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let outgoing = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
        let (incoming, _) = listener.accept().await?;
        let local = ConnectionBuilder::new(Callsign::new("LOCAL")?, PortType::Tcp(outgoing))?;
        let remote = ConnectionBuilder::new(Callsign::new("REMOTE")?, PortType::Tcp(incoming))?;
        tokio::try_join!(local.connect(Callsign::new("REMOTE")?), remote.accept())
    }

    #[tokio::test]
    async fn dropped_completion_does_not_cancel_or_duplicate_write() -> Result<()> {
        let (mut local, mut remote) = client_pair().await?;
        drop(local.write(b"once").await?);
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(2), remote.read()).await??,
            b"once"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), remote.read())
                .await
                .is_err()
        );
        local.disconnect().await?;
        Ok(())
    }

    #[tokio::test]
    async fn completion_wait_can_resume_after_timeout() -> Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut completion = WriteCompletion(rx);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), &mut completion)
                .await
                .is_err()
        );
        tx.send(()).unwrap();
        completion.await?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        drop(tx);
        assert!(matches!(WriteCompletion(rx).await, Err(Error::Io(_))));
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_enqueue_submits_nothing() -> Result<()> {
        let (commands, mut rx) = tokio::sync::mpsc::channel(1);
        let (reply, _completion) = tokio::sync::oneshot::channel();
        commands
            .send(ClientCommand::Write(vec![1], reply))
            .await
            .unwrap();
        let (_tx, received) = tokio::sync::mpsc::channel(1);
        let mut client = Client {
            commands,
            received,
            task_result: std::sync::Arc::new(std::sync::Mutex::new(None)),
            negotiated: None,
        };
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), client.write(&[2]))
                .await
                .is_err()
        );
        assert!(matches!(rx.recv().await, Some(ClientCommand::Write(bytes, _)) if bytes == [1]));
        assert!(rx.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_reads_preserve_data_and_background_progress() -> Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let (mut local, mut remote) = client_pair().await?;
            for _ in 0..3 {
                assert!(
                    tokio::time::timeout(std::time::Duration::from_millis(1), local.read())
                        .await
                        .is_err()
                );
            }
            remote.write(b"background delivery").await?.await?;
            // Neither application's read drives the protocol. Wait until the
            // background task has delivered the packet to the receive queue.
            while local.received.is_empty() {
                tokio::task::yield_now().await;
            }
            assert_eq!(local.read().await?, b"background delivery");
            remote.disconnect().await?;
            assert_eq!(local.read().await?, Vec::<u8>::new());
            assert_eq!(local.read().await?, Vec::<u8>::new());
            local.disconnect().await?;
            Ok::<_, Error>(())
        })
        .await?
    }

    #[tokio::test]
    async fn dropping_client_disconnects_peer_without_application_reads() -> Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let (local, mut remote) = client_pair().await?;
            drop(local);
            assert_eq!(remote.read().await?, Vec::<u8>::new());
            Ok::<_, Error>(())
        })
        .await?
    }

    #[tokio::test]
    async fn background_modem_eof_reaches_reader() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
        let (peer, _) = listener.accept().await?;
        let mut driver = Driver::internal_new(
            state::Data::new(Callsign::new("LOCAL")?),
            PortType::Tcp(port),
            false,
        );
        driver
            .actions(Event::Connect {
                addr: Callsign::new("REMOTE")?,
                ext: false,
            })
            .await?;
        driver
            .actions(Event::Ua(crate::Ua {
                poll: crate::PollFinal::Set,
            }))
            .await?;
        let mut client = Client::spawn(driver);
        drop(peer);
        let error = tokio::time::timeout(std::time::Duration::from_secs(2), client.read())
            .await?
            .unwrap_err();
        assert!(matches!(error, Error::Io(_)));
        Ok(())
    }

    #[tokio::test]
    async fn receive_overflow_disconnects_without_blocking_protocol() -> Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let (mut local, mut remote) = client_pair().await?;
            for byte in 0_u8..128 {
                remote.write(&[byte]).await?.await?;
                while local.received.len() != usize::from(byte) + 1 {
                    tokio::task::yield_now().await;
                }
                // Piggyback acknowledgements without draining local's queue,
                // keeping this test independent of the delayed-ACK timer.
                local.write(b"ack").await?.await?;
                assert_eq!(remote.read().await?, b"ack");
            }
            remote.write(&[128]).await?.await?;
            while !local.commands.is_closed() {
                tokio::task::yield_now().await;
            }
            for byte in 0_u8..128 {
                assert_eq!(local.read().await?, [byte]);
            }
            assert!(matches!(local.read().await, Err(Error::QueueFull)));
            assert_eq!(remote.read().await?, Vec::<u8>::new());
            Ok::<_, Error>(())
        })
        .await?
    }
    use std::time::Duration;

    #[test]
    fn malformed_kiss_frame_does_not_hide_next_packet() -> Result<()> {
        let expected = Packet::ui(Callsign::new("LOCAL")?, Callsign::new("REMOTE")?, b"hello");
        let mut wire = vec![0xc0, 0];
        wire.extend([b'x'; 15]);
        wire.extend([0xdb, 0, 0xc0]);
        wire.extend(crate::escape(&expected.serialize()));
        let packets = kisser_read(&mut wire.into(), Some(false), None);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].packet_type, expected.packet_type);
        Ok(())
    }

    #[test]
    fn eof_detection_preserves_io_errors() {
        let eof = Error::from(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "KISS port closed",
        ));
        assert!(is_error_eof(&eof));
        let Error::Io(source) = &eof else {
            panic!("expected an IO error");
        };
        assert_eq!(source.kind(), std::io::ErrorKind::UnexpectedEof);
        assert_eq!(source.to_string(), "KISS port closed");

        let other = Error::from(std::io::Error::other("read failed"));
        assert!(!is_error_eof(&other));
        let Error::Io(source) = &other else {
            panic!("expected an IO error");
        };
        assert_eq!(source.kind(), std::io::ErrorKind::Other);
        assert_eq!(source.to_string(), "read failed");
        assert!(!is_error_eof(&Error::ConnectionTimeout));
    }

    #[tokio::test]
    async fn invalid_endpoints_return_typed_errors() {
        for (endpoint, reason) in [
            ("tcp://", "empty TCP KISS endpoint"),
            ("serial://", "empty serial KISS endpoint"),
            ("", "KISS endpoint must start with tcp:// or serial://"),
            (
                "udp://localhost:8000",
                "KISS endpoint must start with tcp:// or serial://",
            ),
        ] {
            let Err(Error::InvalidEndpoint {
                endpoint: actual,
                reason: actual_reason,
            }) = connect_kiss_endpoint(endpoint).await
            else {
                panic!("expected an invalid endpoint error for {endpoint:?}");
            };
            assert_eq!(actual, endpoint);
            assert_eq!(actual_reason, reason);
        }
    }

    #[tokio::test]
    async fn tcp_endpoint_failure_preserves_context_and_source() {
        let endpoint = "tcp://127.0.0.1:not-a-port";
        let Err(error @ Error::Endpoint { .. }) = connect_kiss_endpoint(endpoint).await else {
            panic!("expected a TCP endpoint error");
        };
        let Error::Endpoint {
            endpoint: actual,
            source,
        } = &error
        else {
            unreachable!();
        };
        assert_eq!(actual, endpoint);
        assert_eq!(source.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            std::error::Error::source(&error)
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .is_some()
        );
    }

    #[tokio::test]
    async fn invalid_xid_config_emits_no_frames() -> Result<()> {
        for accepting in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let port = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
            let (mut peer, _) = listener.accept().await?;
            let builder = ConnectionBuilder::new(Callsign::new("M0THC-1")?, PortType::Tcp(port))?
                .xid(XidConfig {
                    receive_length: 0,
                    ..Default::default()
                });
            let result = if accepting {
                builder.accept().await
            } else {
                builder.connect(Callsign::new("M0THC-2")?).await
            };
            assert!(matches!(result, Err(Error::InvalidXidConfig(_))));
            let mut buf = [0; 1];
            assert_eq!(peer.read(&mut buf).await?, 0);
        }
        Ok(())
    }

    #[tokio::test]
    async fn xid_connects_and_negotiates_both_modes() -> Result<()> {
        for (mode, local, peer, hint) in [
            (None, "M0THC-1", "M0THC-2", true),
            (Some(false), "M0THC-1", "M0THC-2", true),
            (Some(true), "M0THC-1", "M0THC-2", true),
            (None, "LOCAL-0", "REMOTE-0", true),
            (Some(false), "LOCAL-0", "REMOTE-0", false),
            (Some(true), "LOCAL-0", "REMOTE-0", false),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let client_port = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
            let (server_port, _) = listener.accept().await?;
            let mut client =
                ConnectionBuilder::new(Callsign::new(local)?, PortType::Tcp(client_port))?
                    .xid(XidConfig {
                        management_timeout: Duration::from_millis(20),
                        ..Default::default()
                    })
                    .extended(mode)
                    .srt_default(Duration::from_millis(20));
            let mut server =
                ConnectionBuilder::new(Callsign::new(peer)?, PortType::Tcp(server_port))?;
            if hint {
                client.enable_experiments([Experiment::LinuxExtendedHint]);
                server.enable_experiments([Experiment::LinuxExtendedHint]);
            }
            for builder in [&client, &server] {
                assert_eq!(
                    builder
                        .create_data()
                        .experiments
                        .contains(&Experiment::LinuxExtendedHint),
                    hint
                );
            }
            let (client, server) = tokio::time::timeout(Duration::from_secs(2), async {
                tokio::join!(
                    client.connect(Callsign::new(peer).unwrap()),
                    server.accept()
                )
            })
            .await?;
            let mut client = client?;
            let mut server = server?;
            assert!(client.negotiated_parameters().is_some());
            assert!(server.negotiated_parameters().is_some());
            assert_eq!(
                client.negotiated_parameters().unwrap().extended,
                mode.unwrap_or(true)
            );
            assert_eq!(
                server.negotiated_parameters(),
                client.negotiated_parameters()
            );
            tokio::time::timeout(Duration::from_secs(2), async {
                client.write(b"hello").await?.await?;
                assert_eq!(server.read().await?, b"hello");
                server.write(b"echo").await?.await?;
                assert_eq!(client.read().await?, b"echo");
                Ok::<(), Error>(())
            })
            .await??;
        }
        Ok(())
    }
}
/* vim: textwidth=80
 */
