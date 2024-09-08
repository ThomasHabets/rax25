//! Client code.
//!
//! This file implements the interface for an AX.25 connected mode client.
//! A client struct can (confusingly) be either the initiating or server
//! side of a connection.
//!
//! # Examples
//!
//! ## Client
//!
//! ```no_run
//! use std::sync::Arc;
//! use std::sync::atomic::AtomicBool;
//! use rax25::{Addr, Kiss, Client};
//!
//! let done = Arc::new(AtomicBool::new(false));
//! let kiss = Kiss::new("/dev/rfcomm0")?;
//! let mut client = Client::new(Addr::new("M0THC-1")?, Box::new(kiss));
//! client.connect(&Addr::new("M0THC-2")?, false)?;
//! client.write("Hello\r".as_bytes())?;
//! println!("{:?}", client.read_until(done.clone()));
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! ## Server
//!
//! ```no_run
//! use rax25::{Addr, Kiss, Client, BusKiss, BusHub};
//! use std::sync::{Arc, Mutex};
//!
//! let bus = Arc::new(Mutex::new(bus::Bus::<rax25::BusMessage>::new(10)));
//! let mut bk = BusKiss::new("/dev/ttyS0", bus.clone())?;
//! std::thread::spawn(move || {
//!   bk.run();
//! });
//! let hub = BusHub::new(bus);
//! let mut listener = Client::new(Addr::new("M0THC-1")?, Box::new(hub));
//! let mut con = listener.accept(std::time::Instant::now() +
//! std::time::Duration::from_secs(600))?
//! .expect("connection timeout");
//! eprintln!("Connected!");
//! drop(listener);
//! con.write("Hello client!\n".as_bytes())?;
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//!
use anyhow::{Error, Result};
use log::{debug, error};

use crate::state;
use crate::{Addr, Hub, Packet, PacketType};

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
    pub fn new(me: Addr, kiss: Box<dyn Hub>) -> Self {
        Self {
            kiss,
            eof: false,
            data: state::Data::new(me),
            state: state::new(),
            incoming: std::collections::VecDeque::new(),
        }
    }

    /// Connect to a remote node, optionally using extended (mod-128) mode.
    pub fn connect(&mut self, addr: &Addr, ext: bool) -> Result<()> {
        self.actions(state::Event::Connect(addr.clone(), ext));
        loop {
            let dead = self.data.next_timer_remaining();
            let packet = self
                .kiss
                .recv_timeout(dead.unwrap_or(std::time::Duration::from_secs(60)))?;
            if let Some(packet) = packet {
                let packet = Packet::parse(&packet)?;
                // dbg!(&packet);
                // TODO: check addresses.
                if packet.dst.call() == self.data.me.call() && packet.src.call() == addr.call() {
                    self.actions_packet(&packet)?;
                    if self.state.is_state_connected() {
                        debug!("Connection successful");
                        return Ok(());
                    }
                }
            }
            if self.data.t1_expired() {
                self.actions(state::Event::T1);
            }
            if self.data.t3_expired() {
                self.actions(state::Event::T3);
            }
            if self.state.is_state_disconnected() {
                debug!("Connection timeout");
                return Err(Error::msg("connection timeout"));
            }
        }
    }

    /// Wait for an incoming connection.
    ///
    /// Return a new client for that connection.
    ///
    /// TODO: Not sure Result<Option<_>> is a good pattern. It's not really
    /// compatible with must_use.
    pub fn accept(&mut self, until: std::time::Instant) -> Result<Option<Client>> {
        loop {
            let now = std::time::Instant::now();
            if until < now {
                return Ok(None);
            }
            let packet = self
                .kiss
                .recv_timeout(until.saturating_duration_since(std::time::Instant::now()))?;
            if let Some(packet) = packet {
                if let Ok(packet) = Packet::parse(&packet) {
                    if packet.dst.call() != self.data.me.call() {
                        continue;
                    }
                    match packet.packet_type {
                        PacketType::Sabm(_) => {
                            let mut new_client =
                                Client::new(self.data.me.clone(), self.kiss.clone());
                            new_client.data.peer = Some(packet.src.clone());
                            new_client.data.able_to_establish = true;
                            new_client.actions_packet(&packet)?;
                            return Ok(Some(new_client));
                        }
                        PacketType::Sabme(_) => {
                            let mut new_client =
                                Client::new(self.data.me.clone(), self.kiss.clone());
                            new_client.data.peer = Some(packet.src.clone());
                            new_client.data.set_version_2_2();
                            new_client.data.able_to_establish = true;
                            new_client.actions_packet(&packet)?;
                            return Ok(Some(new_client));
                        }
                        _ => {}
                    }
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
            self.actions(state::Event::Disconnect);
        }
        Ok(())
    }

    /// Write data on an established connection.
    ///
    /// This may block.
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        self.actions(state::Event::Data(data.to_vec()));
        Ok(())
    }

    /// Try reading a raw packet.
    ///
    /// This should normally not be used. Instead use `.write()`.
    ///
    /// Possible uses for this if you're doing lower level stuff.
    fn try_read(&mut self) -> Result<Option<Packet>> {
        let packet = Packet::parse(
            &self
                .kiss
                .recv_timeout(std::time::Duration::from_millis(100))?
                .ok_or(Error::msg("did not get a packet in time"))?,
        )?;
        if packet.src.call() != self.data.peer.as_ref().unwrap().call()
            || packet.dst.call() != self.data.me.call()
        {
            Ok(None)
        } else {
            Ok(Some(packet))
        }
    }

    /// Returns true if remote end has disconnected.
    ///
    /// TODO: really, this maybe should be `.is_connected()`.
    pub fn eof(&self) -> bool {
        self.eof
    }

    /// Read data, or time out after a while.
    ///
    /// Returns an error (possibly timeout error), Some data, or None
    /// if the remote end disconnected.
    ///
    /// I'm not so sure about this return value.
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
                self.actions_packet(&p)?;
            }
        }
        let ret: Vec<_> = self.incoming.iter().cloned().collect();
        self.incoming.clear();
        Ok(Some(ret))
    }

    /// Tell the state machine about a packet.
    ///
    /// If using `try_read()`, then this function should very likely be called
    /// with the received packet.
    fn actions_packet(&mut self, packet: &Packet) -> Result<()> {
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
            PacketType::Xid(p) => self.actions(state::Event::Xid(p.clone())),
            PacketType::Ui(p) => self.actions(state::Event::Ui(p.clone(), packet.command_response)),
            PacketType::Test(p) => self.actions(state::Event::Test(p.clone())),
            PacketType::Dm(p) => self.actions(state::Event::Dm(p.clone())),
            PacketType::Rr(rr) => {
                self.actions(state::Event::Rr(rr.clone(), packet.command_response))
            }
            PacketType::Iframe(iframe) => self.actions(state::Event::Iframe(
                iframe.clone(),
                packet.command_response,
            )),
        }
        Ok(())
    }

    /// Give the state machine any event.
    ///
    /// Events can be incoming packets (probably from `.try_read()` via
    /// `.actions_packet()`), or requests from the application, like
    /// "send this data", or "disconnect".
    ///
    /// State machine side effects are then actioned, including possible
    /// state transitions.
    fn actions(&mut self, event: state::Event) {
        let (state, actions) = state::handle(&*self.state, &mut self.data, &event);
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
                _ => {}
            }

            if let Some(frame) = act.serialize(self.data.ext()) {
                self.kiss.send(&frame).unwrap();
            }
        }
        // TODO: check timers.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Addr, FakeKiss};
    use crate::{Iframe, PacketType, Sabm};

    #[test]
    fn client() -> Result<()> {
        let k = FakeKiss::default();
        let mut c = Client::new(Addr::new("M0THC-1")?, Box::new(k));
        c.data.srt_default = std::time::Duration::from_millis(1);
        c.connect(&Addr::new("M0THC-2")?, false)?;
        c.write(&vec![1, 2, 3])?;
        let reply = c.try_read()?.unwrap();
        assert_eq!(
            reply,
            Packet {
                // TODO: is this even the bit set we expect
                src: Addr::new_bits("M0THC-2", true, false, false, false)?,
                dst: Addr::new_bits("M0THC-1", false, true, false, false)?,
                digipeater: vec![],
                rr_extseq: false,
                command_response: true,
                command_response_la: false,
                rr_dist1: false,
                packet_type: PacketType::Iframe(Iframe {
                    nr: 0,
                    ns: 0,
                    poll: true,
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
        let mut c = Client::new(Addr::new("M0THC-2")?, Box::new(k));
        c.data.srt_default = std::time::Duration::from_millis(1);
        assert!(matches![
            c.accept(std::time::Instant::now() + std::time::Duration::from_millis(1))?,
            None
        ]);
        Ok(())
    }

    #[test]
    fn listen_wrong_dst() -> Result<()> {
        let mut k = FakeKiss::default();
        k.queue.push_back(
            Packet {
                src: Addr::new("M0THC-1")?,
                dst: Addr::new("M0THC-3")?,
                digipeater: vec![],
                rr_extseq: false,
                command_response: true,
                command_response_la: false,
                rr_dist1: false,
                packet_type: PacketType::Sabm(Sabm { poll: true }),
            }
            .serialize(false),
        );
        let mut c = Client::new(Addr::new("M0THC-2")?, Box::new(k));
        c.data.srt_default = std::time::Duration::from_millis(1);
        assert!(matches![
            c.accept(std::time::Instant::now() + std::time::Duration::from_millis(1))?,
            None
        ]);
        Ok(())
    }

    #[test]
    fn listen() -> Result<()> {
        let mut k = FakeKiss::default();
        k.queue.push_back(
            Packet {
                src: Addr::new("M0THC-1")?,
                dst: Addr::new("M0THC-2")?,
                digipeater: vec![],
                rr_extseq: false,
                command_response: true,
                command_response_la: false,
                rr_dist1: false,
                packet_type: PacketType::Sabm(Sabm { poll: true }),
            }
            .serialize(false),
        );
        let mut c = Client::new(Addr::new("M0THC-2")?, Box::new(k));
        c.data.srt_default = std::time::Duration::from_millis(1);
        let _new_conn = c
            .accept(std::time::Instant::now() + std::time::Duration::from_millis(1))?
            .expect("Expected new incoming connection");
        Ok(())
    }
}
