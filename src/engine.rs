//! Shared, single-channel KISS packet engine. The transport is owned once;
//! each callsign pair has its own AX.25 state machine and timers.
use std::collections::{HashMap, VecDeque};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use crate::r#async::PortType;
use crate::{Addr, Callsign, CommandResponse, Packet, PacketType, Result, state};

/// Address pair identifying a link, independently of its digipeater path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Route {
    pub local: Callsign,
    pub remote: Callsign,
}

/// Application identity used to own registrations and AX.25 links.
/// IDs are allocated by the caller and are independent of station callsigns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OwnerId(pub u64);

impl std::fmt::Display for OwnerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Operations submitted to a shared modem engine.
///
/// `owner` identifies an application client, not an AX.25 station. Link events
/// carry this ID so the caller can route them to the appropriate client.
pub enum Command {
    /// Register exclusive ownership of an incoming local callsign.
    /// Replies true for a new registration or a repeat by its current owner;
    /// replies false for an ownership conflict or exhausted registration limit.
    Listen {
        owner: OwnerId,
        local: Callsign,
        reply: oneshot::Sender<bool>,
    },
    /// Unregister a local callsign if it belongs to this owner.
    /// Drops its unannounced links, but leaves established links intact.
    Unlisten { owner: OwnerId, local: Callsign },
    /// Start an outgoing link without requiring callsign registration.
    /// `via` lists digipeaters in transmission order; `extended` selects
    /// modulo-128 instead of modulo-8. Reports establishment or failure through
    /// notifications, including failure if this callsign pair is already used.
    Connect {
        owner: OwnerId,
        route: Route,
        via: Vec<Addr>,
        extended: bool,
    },
    /// Queue application bytes on an established link belonging to this owner.
    /// Write boundaries are not preserved. Unknown, unowned, or unestablished
    /// links are ignored; exceeding the transmit queue limit starts disconnect.
    Write {
        owner: OwnerId,
        route: Route,
        bytes: Vec<u8>,
    },
    /// Initiate AX.25 disconnect for a link belonging to this owner.
    /// Unknown or unowned links are ignored; completion is reported by a
    /// notification rather than an immediate reply.
    Disconnect { owner: OwnerId, route: Route },
    /// Release all callsign registrations and initiate disconnect of every
    /// link belonging to an application client that has gone away.
    RemoveOwner(OwnerId),
    /// Transmit one unconnected UI command with the supplied PID and payload.
    /// Does not create a link, require registration, or retransmit for an ACK.
    Ui {
        local: Callsign,
        remote: Callsign,
        pid: u8,
        bytes: Vec<u8>,
    },
    /// Query buffered and unacknowledged AX.25 data frames, not hardware queues.
    /// With a route, counts only that owner's matching link; without a route,
    /// counts all links on the shared port, ignoring `owner`. Replies with zero
    /// for an unknown or unowned route.
    Pending {
        owner: OwnerId,
        route: Option<Route>,
        reply: oneshot::Sender<usize>,
    },
    /// Reply with the port-wide number of links that announced establishment.
    /// Includes disconnecting links until they are removed, but not attempts
    /// that have yet to establish a connection.
    Active(oneshot::Sender<usize>),
}

/// An engine-to-application event identifying its owning client and link.
///
/// The receiver returned by [`PacketEngine::new`] carries events for all
/// owners. Its consumer must route each notification to `owner`, rather than
/// broadcast it. These are high-level link events, not raw AX.25/KISS frames.
///
/// A [`LinkEvent::Closed`] ends only the identified AX.25 link, not the owner's
/// application transport or other links. Closure of the notification channel
/// instead means the engine's sender has gone away; it is not a link event.
#[derive(Debug)]
pub struct Notification {
    /// Application client to receive this event, including failures of its
    /// outgoing requests that never acquired ownership of a link.
    pub owner: OwnerId,
    /// Link identity, with addresses oriented from this engine's perspective:
    /// `local` is our station and `remote` is the peer, even for received data.
    pub route: Route,
    /// Link lifecycle change or application bytes received from the peer.
    pub event: LinkEvent,
}

/// Application-visible results of connection requests and AX.25 link activity.
/// Protocol control frames and recoverable data-link errors are handled inside
/// the engine rather than exposed as these events.
#[derive(Debug)]
pub enum LinkEvent {
    /// The link has established, reported once for this link's lifetime.
    Connected {
        /// True for an accepted peer-initiated connection; false for a
        /// successful local [`Command::Connect`] request.
        incoming: bool,
    },
    /// Application bytes received from the remote station, in stream order.
    /// Chunk boundaries do not preserve the peer application's write calls.
    Data(Vec<u8>),
    /// A previously established link ended, either normally or after failure.
    /// This does not distinguish who initiated disconnect or close the owning
    /// application's transport; its other links can continue operating.
    Closed,
    /// A connection attempt failed before establishment, or a connect request
    /// was refused because its route is already in use or the engine is full.
    /// Refusing a conflicting request does not terminate the existing link.
    Failed,
}

struct Link {
    owner: OwnerId,
    data: state::Data,
    state: Box<dyn state::State>,
    via: Vec<Addr>,
    incoming: bool,
    announced: bool,
    expires: Option<std::time::Instant>,
}
impl Link {
    fn new(owner: OwnerId, local: Callsign, via: Vec<Addr>, incoming: bool) -> Self {
        let mut data = state::Data::new(local);
        data.able_to_establish = incoming;
        Self {
            owner,
            data,
            state: state::new(),
            via,
            incoming,
            announced: false,
            expires: incoming
                .then(|| std::time::Instant::now() + std::time::Duration::from_secs(30)),
        }
    }
}

/// An engine and bounded command/event channels. Drive `run` continuously.
pub struct PacketEngine {
    commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Notification>,
    listeners: HashMap<Callsign, OwnerId>,
    links: HashMap<Route, Link>,
    capture: Option<crate::pcap::PcapWriter>,
}
impl PacketEngine {
    #[must_use]
    pub fn new() -> (Self, mpsc::Sender<Command>, mpsc::Receiver<Notification>) {
        let (tx, commands) = mpsc::channel(256);
        let (events, rx) = mpsc::channel(256);
        (
            Self {
                commands,
                events,
                listeners: HashMap::new(),
                links: HashMap::new(),
                capture: None,
            },
            tx,
            rx,
        )
    }

    /// Capture transmitted and received AX.25 frames, without KISS framing.
    /// Fails if the path already exists or cannot be created.
    pub fn capture(&mut self, path: std::path::PathBuf) -> Result<()> {
        self.capture = Some(crate::pcap::PcapWriter::create(path)?);
        Ok(())
    }

    async fn step(
        &mut self,
        route: &Route,
        event: state::Event,
        port: &mut PortType,
    ) -> Result<()> {
        let Some(link) = self.links.get_mut(route) else {
            return Ok(());
        };
        let (next, events) = state::handle(&*link.state, &mut link.data, &event);
        if let Some(next) = next {
            link.state = next;
        }
        let connected = link.state.is_state_connected();
        let closed = link.state.is_state_disconnected()
            && !(link.incoming && !link.announced && matches!(event, state::Event::Xid(..)));
        let mut notifications = Vec::new();
        if connected && !link.announced {
            link.announced = true;
            link.expires = None;
            notifications.push(LinkEvent::Connected {
                incoming: link.incoming,
            });
        }
        for event in events {
            match event {
                state::ReturnEvent::Packet(mut p) => {
                    p.digipeater.clone_from(&link.via);
                    let bytes = p.serialize();
                    port.write_all(&crate::escape(&bytes)).await?;
                    if let Some(capture) = &mut self.capture {
                        capture.write(&bytes)?;
                    }
                }
                state::ReturnEvent::Data(state::Res::Some(bytes)) => {
                    notifications.push(LinkEvent::Data(bytes));
                }
                state::ReturnEvent::DlError(error) => log::debug!("{route:?}: {error}"),
                state::ReturnEvent::Data(_) => {}
            }
        }
        if closed {
            notifications.push(if link.announced {
                LinkEvent::Closed
            } else {
                LinkEvent::Failed
            });
        }
        let owner = link.owner;
        for event in notifications {
            self.events
                .send(Notification {
                    owner,
                    route: route.clone(),
                    event,
                })
                .await
                .map_err(|_| crate::Error::QueueFull)?;
        }
        if closed {
            self.links.remove(route);
        }
        Ok(())
    }

    // Exhaustive command dispatch; link behavior lives in step.
    #[allow(clippy::too_many_lines)]
    async fn command(&mut self, command: Command, port: &mut PortType) -> Result<()> {
        match command {
            Command::Listen {
                owner,
                local,
                reply,
            } => {
                if self.listeners.len() >= 256 && !self.listeners.contains_key(&local) {
                    let _ = reply.send(false);
                    return Ok(());
                }
                let entry = self.listeners.entry(local).or_insert(owner);
                let _ = reply.send(*entry == owner);
            }
            Command::Unlisten { owner, local } => {
                if self.listeners.get(&local) == Some(&owner) {
                    self.listeners.remove(&local);
                    self.links.retain(|route, link| {
                        route.local != local || link.announced || link.owner != owner
                    });
                }
            }
            Command::Connect {
                owner,
                route,
                via,
                extended,
            } => {
                if self.links.contains_key(&route) || self.links.len() >= 1024 {
                    self.events
                        .send(Notification {
                            owner,
                            route,
                            event: LinkEvent::Failed,
                        })
                        .await
                        .map_err(|_| crate::Error::QueueFull)?;
                } else {
                    let mut link = Link::new(owner, route.local.clone(), via, false);
                    if extended {
                        link.data.set_version_2_2();
                    } else {
                        link.data.set_version_2();
                    }
                    self.links.insert(route.clone(), link);
                    self.step(
                        &route,
                        state::Event::Connect {
                            addr: route.remote.clone(),
                            ext: extended,
                        },
                        port,
                    )
                    .await?;
                }
            }
            Command::Write {
                owner,
                route,
                bytes,
            } => {
                if self
                    .links
                    .get(&route)
                    .is_some_and(|l| l.owner == owner && l.state.is_state_connected())
                {
                    let full = self
                        .links
                        .get(&route)
                        .is_some_and(|l| l.data.pending_frames() + bytes.len().div_ceil(256) > 256);
                    self.step(
                        &route,
                        if full {
                            state::Event::Disconnect
                        } else {
                            state::Event::Data(bytes)
                        },
                        port,
                    )
                    .await?;
                }
            }
            Command::Disconnect { owner, route } => {
                if self.links.get(&route).is_some_and(|l| l.owner == owner) {
                    self.step(&route, state::Event::Disconnect, port).await?;
                }
            }
            Command::RemoveOwner(owner) => {
                self.listeners.retain(|_, o| *o != owner);
                let routes: Vec<_> = self
                    .links
                    .iter()
                    .filter(|(_, l)| l.owner == owner)
                    .map(|(r, _)| r.clone())
                    .collect();
                for route in routes {
                    self.step(&route, state::Event::Disconnect, port).await?;
                }
            }
            Command::Ui {
                local,
                remote,
                pid,
                bytes,
            } => {
                let mut p = Packet::ui(local, remote, bytes);
                // AGW application transmissions are UI commands, irrespective
                // of Packet::ui's historical response-bit default.
                p.set_command_response(CommandResponse::Command);
                if let PacketType::Ui(ui) = &mut p.packet_type {
                    ui.pid = pid;
                }
                let bytes = p.serialize();
                port.write_all(&crate::escape(&bytes)).await?;
                if let Some(capture) = &mut self.capture {
                    capture.write(&bytes)?;
                }
            }
            Command::Pending {
                owner,
                route,
                reply,
            } => {
                let count = self
                    .links
                    .iter()
                    .filter(|(r, l)| {
                        route
                            .as_ref()
                            .is_none_or(|target| target == *r && l.owner == owner)
                    })
                    .map(|(_, l)| l.data.pending_frames())
                    .sum();
                let _ = reply.send(count);
            }
            Command::Active(reply) => {
                let _ = reply.send(self.links.values().filter(|l| l.announced).count());
            }
        }
        Ok(())
    }

    async fn frame(&mut self, bytes: &[u8], port: &mut PortType) -> Result<()> {
        if bytes.len() < 15 {
            return Ok(());
        }
        let local = Addr::parse(&bytes[..7])?.callsign().clone();
        let remote = Addr::parse(&bytes[7..14])?.callsign().clone();
        let route = Route { local, remote };
        let ext = self.links.get(&route).map(|l| l.data.ext());
        let p = Packet::parse(bytes, ext)?;
        if p.digipeater
            .iter()
            .any(|a| !a.flags.contains(crate::AddrFlags::HIGH))
        {
            return Ok(());
        }
        if !self.links.contains_key(&route) {
            let Some(&owner) = self.listeners.get(&route.local) else {
                return Ok(());
            };
            if self.links.len() >= 1024
                || !matches!(
                    p.packet_type(),
                    PacketType::Sabm(_) | PacketType::Sabme(_) | PacketType::Xid(_)
                )
            {
                return Ok(());
            }
            let via = p
                .digipeater
                .iter()
                .rev()
                .cloned()
                .map(|a| a.with_highbit(false))
                .collect();
            self.links.insert(
                route.clone(),
                Link::new(owner, route.local.clone(), via, true),
            );
        }
        self.step(&route, packet_event(&p), port).await
    }

    /// Drive until the modem fails or all command senders are dropped.
    pub async fn run(mut self, mut port: PortType) -> Result<()> {
        let mut input = VecDeque::new();
        let mut buf = [0; 4096];
        loop {
            self.links.retain(|_, link| {
                link.expires
                    .is_none_or(|expiry| expiry > std::time::Instant::now())
            });
            let delay = self
                .links
                .values()
                .filter_map(|l| l.data.next_timer_remaining())
                .chain(self.links.values().filter_map(|l| {
                    l.expires
                        .map(|expiry| expiry.saturating_duration_since(std::time::Instant::now()))
                }))
                .min()
                .unwrap_or(std::time::Duration::from_secs(3600));
            tokio::select! {
                command = self.commands.recv() => {
                    let Some(command) = command else { return Ok(()); };
                    self.command(command, &mut port).await?;
                }
                n = port.read(&mut buf) => {
                    let n = n?;
                    if n == 0 { return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into()); }
                    input.extend(&buf[..n]);
                    while let Some((start, end)) = crate::find_frame(&input) {
                        if end <= start + 2 { input.drain(..end.max(1)); continue; }
                        let bytes: Vec<_> = input.iter().skip(start + 2).take(end - start - 2).copied().collect();
                        let command = input.get(start + 1).copied();
                        input.drain(..end);
                        if command == Some(0) {
                            match crate::unescape(&bytes) {
                                Ok(bytes) => {
                                    if let Some(capture) = &mut self.capture {
                                        capture.write(&bytes)?;
                                    }
                                    if let Err(error) = self.frame(&bytes, &mut port).await {
                                    if matches!(error, crate::Error::Io(_) | crate::Error::QueueFull) { return Err(error); }
                                    log::warn!("KISS frame: {error}");
                                    }
                                },
                                Err(error) => log::warn!("KISS framing: {error}"),
                            }
                        }
                    }
                    if input.len() > 131_072 { input.clear(); }
                }
                () = tokio::time::sleep(delay) => {
                    let timers: Vec<_> = self.links.iter().map(|(r, l)| (r.clone(), l.data.active_timers())).collect();
                    for (route, events) in timers { for event in events { self.step(&route, event, &mut port).await?; } }
                }
            }
        }
    }
}

pub(crate) fn packet_event(p: &Packet) -> state::Event {
    use state::Event as E;
    let cr = CommandResponse::from(p.command_response());
    match &p.packet_type {
        PacketType::Sabm(v) => E::Sabm(v.clone(), p.src.callsign().clone()),
        PacketType::Sabme(v) => E::Sabme(v.clone(), p.src.callsign().clone()),
        PacketType::Ua(v) => E::Ua(v.clone()),
        PacketType::Dm(v) => E::Dm(v.clone()),
        PacketType::Disc(v) => E::Disc(v.clone()),
        PacketType::Iframe(v) => E::Iframe(v.clone(), cr),
        PacketType::Rr(v) => E::Rr(v.clone(), cr),
        PacketType::Rnr(v) => E::Rnr(v.clone()),
        PacketType::Rej(v) => E::Rej(v.clone(), cr),
        PacketType::Srej(v) => E::Srej(v.clone()),
        PacketType::Frmr(v) => E::Frmr(v.clone()),
        PacketType::Ui(v) => E::Ui(v.clone(), cr),
        PacketType::Test(v) => E::Test(v.clone(), cr),
        PacketType::Xid(v) => E::Xid(v.clone(), cr, p.src.callsign().clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};
    fn call(s: &str) -> Callsign {
        Callsign::new(s).unwrap()
    }
    async fn ports() -> (PortType, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        (PortType::Tcp(socket), peer)
    }
    async fn register(engine: &mut PacketEngine, port: &mut PortType, owner: OwnerId) -> bool {
        let (reply, rx) = oneshot::channel();
        engine
            .command(
                Command::Listen {
                    owner,
                    local: call("LOCAL"),
                    reply,
                },
                port,
            )
            .await
            .unwrap();
        rx.await.unwrap()
    }
    async fn received(peer: &mut TcpStream) -> Packet {
        let mut input = VecDeque::new();
        let mut buf = [0; 4096];
        loop {
            let n = tokio::time::timeout(std::time::Duration::from_secs(1), peer.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_ne!(n, 0);
            input.extend(&buf[..n]);
            if let Some((start, end)) = crate::find_frame(&input) {
                let bytes: Vec<_> = input
                    .iter()
                    .skip(start + 2)
                    .take(end - start - 2)
                    .copied()
                    .collect();
                return Packet::parse(&crate::unescape(&bytes).unwrap(), None).unwrap();
            }
        }
    }
    #[tokio::test]
    async fn exclusive_registration_cleanup_and_ui_pid() {
        let (mut engine, _tx, _rx) = PacketEngine::new();
        let (mut port, mut peer) = ports().await;
        assert!(register(&mut engine, &mut port, OwnerId(1)).await);
        assert!(register(&mut engine, &mut port, OwnerId(1)).await);
        assert!(!register(&mut engine, &mut port, OwnerId(2)).await);
        engine
            .command(Command::RemoveOwner(OwnerId(1)), &mut port)
            .await
            .unwrap();
        assert!(register(&mut engine, &mut port, OwnerId(2)).await);
        engine
            .command(
                Command::Ui {
                    local: call("LOCAL"),
                    remote: call("REMOTE"),
                    pid: 0xcc,
                    bytes: vec![0xc0, 0xdb, 0, 255],
                },
                &mut port,
            )
            .await
            .unwrap();
        let packet = received(&mut peer).await;
        assert!(packet.command_response());
        assert!(matches!(packet.packet_type,
            PacketType::Ui(crate::Ui { pid: 0xcc, ref payload, .. }) if payload == &[0xc0, 0xdb, 0, 255]));
    }
    #[tokio::test]
    async fn incoming_routes_and_simultaneous_link_ownership() {
        let (mut engine, _tx, mut rx) = PacketEngine::new();
        let (mut port, mut peer) = ports().await;
        assert!(register(&mut engine, &mut port, OwnerId(7)).await);
        for remote in ["REMOTE", "OTHER"] {
            let mut p = Packet::ui(call(remote), call("LOCAL"), []);
            p.set_command_response(CommandResponse::Command);
            p.packet_type = PacketType::Sabm(crate::Sabm {
                poll: crate::PollFinal::Set,
            });
            p.digipeater = ["HOP1", "HOP2"]
                .into_iter()
                .map(|s| Addr::new(s).unwrap().with_highbit(true))
                .collect();
            engine.frame(&p.serialize(), &mut port).await.unwrap();
            let reply = received(&mut peer).await;
            assert_eq!(
                reply.digipeater.iter().map(Addr::call).collect::<Vec<_>>(),
                ["HOP2", "HOP1"]
            );
            assert!(
                reply
                    .digipeater
                    .iter()
                    .all(|a| !a.flags.contains(crate::AddrFlags::HIGH))
            );
            let n = rx.recv().await.unwrap();
            assert_eq!(n.owner, OwnerId(7));
            assert!(matches!(n.event, LinkEvent::Connected { incoming: true }));
            engine
                .command(
                    Command::Connect {
                        owner: OwnerId(8),
                        route: n.route,
                        via: vec![],
                        extended: false,
                    },
                    &mut port,
                )
                .await
                .unwrap();
            assert!(matches!(
                rx.recv().await.unwrap(),
                Notification {
                    owner: OwnerId(8),
                    event: LinkEvent::Failed,
                    ..
                }
            ));
        }
        assert_eq!(engine.links.len(), 2);
        let route = Route {
            local: call("LOCAL"),
            remote: call("REMOTE"),
        };
        engine
            .command(
                Command::Write {
                    owner: OwnerId(7),
                    route: route.clone(),
                    bytes: b"queued".to_vec(),
                },
                &mut port,
            )
            .await
            .unwrap();
        let _ = received(&mut peer).await;
        for (owner, expected) in [(OwnerId(7), 1), (OwnerId(8), 0)] {
            let (reply, count) = oneshot::channel();
            engine
                .command(
                    Command::Pending {
                        owner,
                        route: Some(route.clone()),
                        reply,
                    },
                    &mut port,
                )
                .await
                .unwrap();
            assert_eq!(count.await.unwrap(), expected);
        }
        engine
            .command(
                Command::Unlisten {
                    owner: OwnerId(7),
                    local: call("LOCAL"),
                },
                &mut port,
            )
            .await
            .unwrap();
        assert_eq!(engine.links.len(), 2); // Accepted links survive unregister.
    }
}
