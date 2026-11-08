//! Synchronous API.
//!
//! This file implements the sync interface for an AX.25 connected mode client.
//! A client struct can (confusingly) be either the initiating or server side of
//! a connection.
//!
//! # Examples
//!
//! ## Client
//!
//! ```no_run
//! use std::sync::atomic::AtomicBool;
//! use std::sync::Arc;
//!
//! use rax25::sync::Client;
//! use rax25::{Callsign, Kiss};
//!
//! let done = Arc::new(AtomicBool::new(false));
//! let kiss = Kiss::new("/dev/rfcomm0")?;
//! let mut client = Client::new(Callsign::new("M0THC-1")?, Box::new(kiss));
//! client.connect(&Callsign::new("M0THC-2")?, false)?;
//! client.write("Hello\r".as_bytes())?;
//! println!("{:?}", client.read_until(done.clone()));
//! # rax25::Result::<()>::Ok(())
//! ```
//!
//! ## Server
//!
//! ```no_run
//! use std::sync::{Arc, Mutex};
//!
//! use rax25::sync::Client;
//! use rax25::{Callsign, BusHub, BusKiss, Kiss};
//!
//! let bus = Arc::new(Mutex::new(bus::Bus::<rax25::BusMessage>::new(10)));
//! let mut bk = BusKiss::new("/dev/ttyS0", bus.clone())?;
//! std::thread::spawn(move || {
//!     bk.run();
//! });
//! let hub = BusHub::new(bus);
//! let mut listener = Client::new(Callsign::new("M0THC-1")?, Box::new(hub));
//! let mut con = listener
//!     .accept(std::time::Instant::now() + std::time::Duration::from_secs(600))?
//!     .expect("connection timeout");
//! eprintln!("Connected!");
//! drop(listener);
//! con.write("Hello client!\n".as_bytes())?;
//! # rax25::Result::<()>::Ok(())
//! ```
use crate::{Error, Result};
use log::{debug, error};

use crate::state;
use crate::{Callsign, CommandResponse, Hub, Packet, PacketType};

/// A connected mode client.
///
/// `.read_until()` MUST be called fairly often (how often depends on T1 and
/// T3 of local and remote endpoint), in order to drain the KISS packet queue
/// and respond to remote peer queries like RR, or to see any received DISC.
///
/// A future `async` interface will make this cleaner.
#[must_use]
pub struct Client {
    kiss: Box<dyn Hub>,
    pub(crate) data: state::Data,
    state: Box<dyn state::State>,
    eof: bool,

    incoming: std::collections::VecDeque<u8>,
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Err(e) = self.disconnect() {
            error!("Error disconnecting on drop: {e}");
        }
    }
}

impl Client {
    /// Create a new client with the given local address, using the given
    /// KISS interface for incoming and outgoing frames.
    pub fn new(me: Callsign, kiss: Box<dyn Hub>) -> Self {
        Self {
            kiss,
            eof: false,
            data: state::Data::new(me),
            state: state::new(),
            incoming: std::collections::VecDeque::new(),
        }
    }

    /// Enable the outgoing Linux extended-mode address hint (default true).
    /// This does not change the sequencing mode or receive parsing.
    pub fn set_linux_extended_hint(&mut self, enabled: bool) {
        self.data.set_linux_extended_hint(enabled);
    }

    /// Configure XID negotiation for subsequent connections.
    pub fn set_xid_config(&mut self, config: state::XidConfig) {
        self.data.set_xid_config(config);
    }

    /// Parameters negotiated by XID, or `None` for an unnegotiated link.
    #[must_use]
    pub fn negotiated_parameters(&self) -> Option<&state::NegotiatedParameters> {
        self.data.negotiated_parameters()
    }

    /// Negotiate parameters before connecting. `None` prefers extended mode;
    /// `Some` constrains the offered mode. Legacy peers fall back to standard.
    pub fn connect_with_xid(&mut self, addr: &Callsign, ext: Option<bool>) -> Result<()> {
        self.data.validate_xid_config()?;
        self.actions(&state::Event::ConnectWithXid {
            addr: addr.clone(),
            ext,
        });
        self.wait_connected(addr)
    }

    /// Connect to a remote node, optionally using extended (mod-128) mode.
    pub fn connect(&mut self, addr: &Callsign, ext: bool) -> Result<()> {
        self.data.validate_xid_config()?;
        self.actions(&state::Event::Connect {
            addr: addr.clone(),
            ext,
        });
        self.wait_connected(addr)
    }

    fn wait_connected(&mut self, addr: &Callsign) -> Result<()> {
        loop {
            let dead = self.data.next_timer_remaining();
            let packet = self
                .kiss
                .recv_timeout(dead.unwrap_or(std::time::Duration::from_mins(1)))?;
            if let Some(packet) = packet {
                let packet = Packet::parse(&packet, Some(self.data.ext()))?;
                // dbg!(&packet);
                // TODO: check addresses.
                if packet.dst.callsign() == &self.data.me && packet.src.callsign() == addr {
                    self.actions_packet(&packet);
                    if self.state.is_state_connected() {
                        debug!("Connection successful");
                        return Ok(());
                    }
                }
            }
            if self.data.t1_expired() {
                self.actions(&state::Event::T1);
            }
            if self.data.t3_expired() {
                self.actions(&state::Event::T3);
            }
            if self.data.management_expired() {
                self.actions(&state::Event::ManagementTimeout);
            }
            if self.state.is_state_disconnected() {
                debug!("Connection timeout");
                return Err(Error::ConnectionTimeout);
            }
        }
    }

    /// Wait for an incoming connection.
    ///
    /// Return a new client for that connection.
    ///
    /// TODO: Not sure Result<Option<_>> is a good pattern. It's not really
    /// compatible with `must_use`.
    pub fn accept(&mut self, until: std::time::Instant) -> Result<Option<Client>> {
        self.data.validate_xid_config()?;
        self.data.able_to_establish = true;
        loop {
            let now = std::time::Instant::now();
            if until < now {
                return Ok(None);
            }
            let packet = self
                .kiss
                .recv_timeout(until.saturating_duration_since(std::time::Instant::now()))?;
            if let Some(packet) = packet
                && let Ok(packet) = Packet::parse(&packet, None)
            {
                if packet.dst.callsign() != &self.data.me {
                    continue;
                }
                match &packet.packet_type {
                    PacketType::Xid(_) => {
                        self.actions_packet(&packet);
                    }
                    PacketType::Sabm(_) | PacketType::Sabme(_) => {
                        let mut new_client = Client::new(self.data.me.clone(), self.kiss.clone());
                        new_client.data = self.data.accepted_data(packet.src.callsign());
                        new_client.data.peer = Some(packet.src.callsign().clone());
                        new_client.data.able_to_establish = true;
                        if matches!(&packet.packet_type, PacketType::Sabme(_)) {
                            new_client.data.set_version_2_2();
                        }
                        new_client.actions_packet(&packet);
                        if new_client.state.is_state_connected() {
                            return Ok(Some(new_client));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Disconnect an ongoing connection.
    ///
    /// Currently does not wait for the remote end to send UA, but that may
    /// change.
    pub fn disconnect(&mut self) -> Result<()> {
        if !self.state.is_state_disconnected() {
            self.actions(&state::Event::Disconnect);
        }
        Ok(())
    }

    /// Write data on an established connection.
    ///
    /// This may block.
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        self.actions(&state::Event::Data(data.to_vec()));
        Ok(())
    }

    /// Try reading a raw packet.
    ///
    /// This should normally not be used. Instead use `.write()`.
    ///
    /// Possible uses for this if you're doing lower level stuff.
    fn try_read(&mut self) -> Result<Option<Packet>> {
        let timeout = self
            .data
            .next_timer_remaining()
            .unwrap_or(std::time::Duration::from_millis(100))
            .min(std::time::Duration::from_millis(100));
        let Some(bytes) = self.kiss.recv_timeout(timeout)? else {
            return Ok(None);
        };
        let packet = Packet::parse(&bytes, Some(self.data.ext()))?;
        if packet.src.callsign() != self.data.peer.as_ref().unwrap()
            || packet.dst.callsign() != &self.data.me
        {
            Ok(None)
        } else {
            Ok(Some(packet))
        }
    }

    /// Returns true if remote end has disconnected.
    ///
    /// TODO: really, this maybe should be `.is_connected()`.
    #[must_use]
    pub fn eof(&self) -> bool {
        self.eof
    }

    /// Read data, or time out after a while.
    ///
    /// Returns an error (possibly timeout error), Some data, or None
    /// if the remote end disconnected.
    ///
    /// `done` is `Arc` to make it easier for caller to cancel from other
    /// threads / lifetimes.
    ///
    /// I'm not so sure about this return value.
    #[allow(clippy::needless_pass_by_value)]
    pub fn read_until(
        &mut self,
        done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<Option<Vec<u8>>> {
        while self.incoming.is_empty() {
            if self.eof {
                return Ok(None);
            }
            if done.load(std::sync::atomic::Ordering::SeqCst) {
                return Ok(None);
            }
            if let Some(p) = self.try_read()? {
                self.actions_packet(&p);
            }
            if self.data.t1_expired() {
                self.actions(&state::Event::T1);
            }
            if self.data.t3_expired() {
                self.actions(&state::Event::T3);
            }
            if self.data.management_expired() {
                self.actions(&state::Event::ManagementTimeout);
            }
        }
        let ret: Vec<_> = self.incoming.iter().copied().collect();
        self.incoming.clear();
        Ok(Some(ret))
    }

    /// Tell the state machine about a packet.
    ///
    /// If using `try_read()`, then this function should very likely be called
    /// with the received packet.
    fn actions_packet(&mut self, packet: &Packet) {
        match &packet.packet_type {
            PacketType::Sabm(p) => self.actions(&state::Event::Sabm(
                p.clone(),
                packet.src.callsign().clone(),
            )),
            PacketType::Sabme(p) => {
                self.actions(&state::Event::Sabme(
                    p.clone(),
                    packet.src.callsign().clone(),
                ));
            }
            PacketType::Ua(ua) => self.actions(&state::Event::Ua(ua.clone())),
            PacketType::Disc(p) => self.actions(&state::Event::Disc(p.clone())),
            PacketType::Rnr(p) => self.actions(&state::Event::Rnr(p.clone())),
            PacketType::Rej(p) => {
                self.actions(&state::Event::Rej(
                    p.clone(),
                    CommandResponse::from(packet.command_response()),
                ));
            }
            PacketType::Srej(p) => self.actions(&state::Event::Srej(p.clone())),
            PacketType::Frmr(p) => self.actions(&state::Event::Frmr(p.clone())),
            PacketType::Xid(p) => {
                self.actions(&state::Event::Xid(
                    p.clone(),
                    CommandResponse::from(packet.command_response()),
                    packet.src.callsign().clone(),
                ));
            }
            PacketType::Ui(p) => {
                self.actions(&state::Event::Ui(
                    p.clone(),
                    CommandResponse::from(packet.command_response()),
                ));
            }
            PacketType::Test(p) => {
                self.actions(&state::Event::Test(
                    p.clone(),
                    CommandResponse::from(packet.command_response()),
                ));
            }
            PacketType::Dm(p) => self.actions(&state::Event::Dm(p.clone())),
            PacketType::Rr(rr) => {
                self.actions(&state::Event::Rr(
                    rr.clone(),
                    CommandResponse::from(packet.command_response()),
                ));
            }
            PacketType::Iframe(iframe) => self.actions(&state::Event::Iframe(
                iframe.clone(),
                CommandResponse::from(packet.command_response()),
            )),
        }
    }

    /// Give the state machine any event.
    ///
    /// Events can be incoming packets (probably from `.try_read()` via
    /// `.actions_packet()`), or requests from the application, like
    /// "send this data", or "disconnect".
    ///
    /// State machine side effects are then actioned, including possible
    /// state transitions.
    fn actions(&mut self, event: &state::Event) {
        let (state, actions) = state::handle(&*self.state, &mut self.data, event);
        if let Some(state) = state {
            let _ = std::mem::replace(&mut self.state, state);
        }
        for act in actions {
            match &act {
                state::ReturnEvent::DlError(e) => {
                    eprintln!("DLError: {e:?}");
                }
                state::ReturnEvent::Data(res) => match res {
                    state::Res::None => {}
                    state::Res::EOF => self.eof = true,
                    state::Res::Some(d) => {
                        debug!("DATA DELIVERED>>> {:?}", String::from_utf8(d.clone()));
                        self.incoming.extend(d);
                    }
                },
                state::ReturnEvent::Packet(_) => {}
            }

            if let Some(frame) =
                act.serialize_with_linux_extended_hint(self.data.linux_extended_hint)
            {
                self.kiss.send(&frame).unwrap();
            }
        }
        // TODO: check timers.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Callsign, FakeKiss, PollFinal};
    use crate::{Iframe, PacketType, Sabm};

    #[derive(Clone, Default)]
    struct XidPeer {
        queue: std::collections::VecDeque<Vec<u8>>,
        sent: std::rc::Rc<std::cell::RefCell<Vec<Packet>>>,
        respond: bool,
    }

    impl Hub for XidPeer {
        fn send(&mut self, frame: &[u8]) -> Result<()> {
            let packet = Packet::parse(frame, Some(false))?;
            self.sent.borrow_mut().push(packet.clone());
            let reply = match &packet.packet_type {
                PacketType::Xid(xid) if packet.command_response() && self.respond => {
                    Some(PacketType::Xid(xid.clone()))
                }
                PacketType::Sabm(_) | PacketType::Sabme(_) => Some(PacketType::Ua(crate::Ua {
                    poll: PollFinal::Set,
                })),
                _ => None,
            };
            if let Some(packet_type) = reply {
                let mut reply = packet;
                std::mem::swap(&mut reply.src, &mut reply.dst);
                reply.set_command_response(CommandResponse::Response);
                reply.packet_type = packet_type;
                self.queue.push_back(reply.serialize());
            }
            Ok(())
        }

        fn recv_timeout(&mut self, timeout: std::time::Duration) -> Result<Option<Vec<u8>>> {
            if let Some(packet) = self.queue.pop_front() {
                return Ok(Some(packet));
            }
            std::thread::sleep(timeout);
            Ok(None)
        }

        fn clone(&self) -> Box<dyn Hub> {
            Box::new(Self {
                queue: std::collections::VecDeque::default(),
                ..Clone::clone(self)
            })
        }
    }

    #[test]
    fn xid_fake_peer_negotiates_both_modes() -> Result<()> {
        for (mode, hint) in [
            (None, true),
            (Some(false), true),
            (Some(true), true),
            (None, false),
            (Some(false), false),
            (Some(true), false),
        ] {
            let peer = XidPeer {
                respond: true,
                ..Default::default()
            };
            let sent = peer.sent.clone();
            let mut client = Client::new(Callsign::new("M0THC-1")?, Box::new(peer));
            assert!(client.data.linux_extended_hint);
            client.set_linux_extended_hint(hint);
            client.set_xid_config(state::XidConfig {
                management_timeout: std::time::Duration::from_millis(20),
                ..Default::default()
            });
            client.connect_with_xid(&Callsign::new("M0THC-2")?, mode)?;
            assert!(client.negotiated_parameters().is_some());
            assert_eq!(client.data.ext(), mode.unwrap_or(true));
            let sent = sent.borrow();
            assert!(matches!(sent[0].packet_type, PacketType::Xid(_)));
            assert!(matches!(
                sent[1].packet_type,
                PacketType::Sabm(_) | PacketType::Sabme(_)
            ));
            assert_eq!(
                sent[1].src.flags.contains(crate::AddrFlags::EXTENDED),
                mode.unwrap_or(true) && hint
            );
        }
        Ok(())
    }

    #[test]
    fn xid_fake_peer_timeout_falls_back_to_standard() -> Result<()> {
        let peer = XidPeer::default();
        let sent = peer.sent.clone();
        let mut client = Client::new(Callsign::new("M0THC-1")?, Box::new(peer));
        client.set_xid_config(state::XidConfig {
            management_timeout: std::time::Duration::from_millis(1),
            management_retries: 1,
            ..Default::default()
        });
        client.connect_with_xid(&Callsign::new("M0THC-2")?, Some(true))?;
        assert!(!client.data.ext());
        assert!(client.negotiated_parameters().is_none());
        let sent = sent.borrow();
        assert!(matches!(sent[0].packet_type, PacketType::Xid(_)));
        assert!(matches!(
            sent.last().unwrap().packet_type,
            PacketType::Sabm(_)
        ));
        Ok(())
    }

    #[test]
    fn invalid_xid_config_emits_no_frames() -> Result<()> {
        let peer = XidPeer::default();
        let sent = peer.sent.clone();
        let mut client = Client::new(Callsign::new("M0THC-1")?, Box::new(peer));
        client.set_xid_config(state::XidConfig {
            receive_length: 0,
            ..Default::default()
        });
        let remote = Callsign::new("M0THC-2")?;
        assert!(client.connect_with_xid(&remote, None).is_err());
        assert!(client.connect(&remote, false).is_err());
        assert!(client.accept(std::time::Instant::now()).is_err());
        assert!(sent.borrow().is_empty());
        Ok(())
    }

    #[test]
    fn listener_processes_xid_before_sabm() -> Result<()> {
        // Reuse a real initiator offer, so this test exercises both API paths.
        let probe = XidPeer {
            respond: true,
            ..Default::default()
        };
        let sent = probe.sent.clone();
        let mut initiator = Client::new(Callsign::new("M0THC-1")?, Box::new(probe));
        initiator.set_xid_config(state::XidConfig {
            management_timeout: std::time::Duration::from_millis(20),
            ..Default::default()
        });
        initiator.connect_with_xid(&Callsign::new("M0THC-2")?, Some(false))?;
        let frames: Vec<_> = sent.borrow().iter().map(Packet::serialize).collect();
        let peer = XidPeer {
            queue: frames.into(),
            ..Default::default()
        };
        let responses = peer.sent.clone();
        let mut listener = Client::new(Callsign::new("M0THC-2")?, Box::new(peer));
        let accepted = listener
            .accept(std::time::Instant::now() + std::time::Duration::from_secs(1))?
            .expect("incoming connection");
        assert!(accepted.negotiated_parameters().is_some());
        let responses = responses.borrow();
        assert!(matches!(responses[0].packet_type, PacketType::Xid(_)));
        assert!(!responses[0].command_response());
        assert!(matches!(responses[1].packet_type, PacketType::Ua(_)));
        Ok(())
    }

    #[test]
    fn plain_reconnect_does_not_reuse_consumed_xid_proposal() -> Result<()> {
        let probe = XidPeer {
            respond: true,
            ..Default::default()
        };
        let sent = probe.sent.clone();
        let mut initiator = Client::new(Callsign::new("M0THC-1")?, Box::new(probe));
        initiator.set_xid_config(state::XidConfig {
            receive_length: 8,
            management_timeout: std::time::Duration::from_millis(20),
            ..Default::default()
        });
        initiator.connect_with_xid(&Callsign::new("M0THC-2")?, Some(false))?;
        let mut frames: Vec<_> = sent.borrow().iter().map(Packet::serialize).collect();
        // Reconnect immediately with SABM alone, before the pending offer expires.
        frames.push(frames.last().expect("initial SABM").clone());
        let peer = XidPeer {
            queue: frames.into(),
            ..Default::default()
        };
        let responses = peer.sent.clone();
        let mut listener = Client::new(Callsign::new("M0THC-2")?, Box::new(peer));
        let until = std::time::Instant::now() + std::time::Duration::from_secs(1);
        let mut negotiated = listener.accept(until)?.expect("negotiated connection");
        assert!(negotiated.negotiated_parameters().is_some());
        let start = responses.borrow().len();
        negotiated.write(b"0123456789abcdef")?;
        let lengths: Vec<_> = responses.borrow()[start..]
            .iter()
            .filter_map(|packet| {
                if let PacketType::Iframe(frame) = &packet.packet_type {
                    Some(frame.payload.len())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(lengths, [8, 8]);
        drop(negotiated);

        let mut plain = listener.accept(until)?.expect("plain reconnection");
        assert!(plain.negotiated_parameters().is_none());
        assert!(!plain.data.ext());
        let start = responses.borrow().len();
        plain.write(b"0123456789abcdef")?;
        let responses = responses.borrow();
        assert_eq!(responses.len(), start + 1);
        let PacketType::Iframe(frame) = &responses[start].packet_type else {
            panic!("expected unfragmented information frame");
        };
        assert_eq!(frame.payload, b"0123456789abcdef");
        Ok(())
    }

    #[test]
    fn client() -> Result<()> {
        let k = FakeKiss::default();
        let mut c = Client::new(Callsign::new("M0THC-1")?, Box::new(k));
        c.data.srt_default = std::time::Duration::from_millis(1);
        c.connect(&Callsign::new("M0THC-2")?, false)?;
        c.write(&[1, 2, 3])?;
        let reply = c.try_read()?.unwrap();
        assert_eq!(
            reply,
            Packet {
                // TODO: is this even the bit set we expect
                src: crate::Addr::new_bits("M0THC-2", crate::AddrFlags::LAST)?.with_highbit(false),
                dst: crate::Addr::new_bits("M0THC-1", crate::AddrFlags::HIGH)?.with_highbit(true),
                digipeater: vec![],
                modulus: state::Modulus::Standard,
                packet_type: PacketType::Iframe(Iframe {
                    nr: 0,
                    ns: 0,
                    poll: PollFinal::Set,
                    pid: 240,
                    payload: vec![3, 2, 1],
                },),
            }
        );
        Ok(())
    }

    #[test]
    fn listen_timeout() -> Result<()> {
        let k = FakeKiss::default();
        let mut c = Client::new(Callsign::new("M0THC-2")?, Box::new(k));
        c.data.srt_default = std::time::Duration::from_millis(1);
        assert!(
            c.accept(std::time::Instant::now() + std::time::Duration::from_millis(1))?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn listen_wrong_dst() -> Result<()> {
        let mut k = FakeKiss::default();
        k.queue.push_back(
            Packet {
                src: crate::Addr::from(Callsign::new("M0THC-1")?).with_highbit(false),
                dst: crate::Addr::from(Callsign::new("M0THC-3")?).with_highbit(true),
                digipeater: vec![],
                modulus: state::Modulus::Standard,
                packet_type: PacketType::Sabm(Sabm {
                    poll: PollFinal::Set,
                }),
            }
            .serialize(),
        );
        let mut c = Client::new(Callsign::new("M0THC-2")?, Box::new(k));
        c.data.srt_default = std::time::Duration::from_millis(1);
        assert!(
            c.accept(std::time::Instant::now() + std::time::Duration::from_millis(1))?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn listen() -> Result<()> {
        let mut k = FakeKiss::default();
        k.queue.push_back(
            Packet {
                src: crate::Addr::from(Callsign::new("M0THC-1")?).with_highbit(false),
                dst: crate::Addr::from(Callsign::new("M0THC-2")?).with_highbit(true),
                digipeater: vec![],
                modulus: state::Modulus::Standard,
                packet_type: PacketType::Sabm(Sabm {
                    poll: PollFinal::Set,
                }),
            }
            .serialize(),
        );
        let mut c = Client::new(Callsign::new("M0THC-2")?, Box::new(k));
        c.data.srt_default = std::time::Duration::from_millis(1);
        let _new_conn = c
            .accept(std::time::Instant::now() + std::time::Duration::from_millis(1))?
            .expect("Expected new incoming connection");
        Ok(())
    }
}
/* vim: textwidth=80
 */
