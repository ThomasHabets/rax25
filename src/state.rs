//! State machine code for AX.25
//!
//! The state machine is documented in https://www.tapr.org/pdf/AX25.2.2.pdf,
//! but it has a few bugs. They're pointed out in the code as they are
//! encountered.
//!
//! There's also the 2017 version, but it quite possibly added more bugs than it
//! fixed:
//! https://wiki.oarc.uk/_media/packet:ax25.2.2.10.pd
//!
//! All page numbers, unless otherwise specified, are for the 1998 PDF.
//!
//! There's also isomer's useful notes at the top of
//! https://github.com/isomer/ax25embed/blob/main/ax25/ax25_dl.c
use std::collections::VecDeque;

use anyhow::Result;
use log::{debug, warn};

use crate::{
    Addr, Disc, Dm, Frmr, Iframe, Packet, PacketType, Rej, Rnr, Rr, Sabm, Sabme, Srej, Test, Ua,
    Ui, Xid,
};

/// Incoming events to the state machine.
///
/// An incoming event is an incoming packet, or a command from the application,
/// like "connect", or "send this data".
#[derive(Debug, PartialEq)]
pub enum Event {
    Connect(Addr, /* extended */ bool),
    Disconnect,
    Data(Vec<u8>),
    T1,
    T3,
    Sabm(Sabm, /* peer */ Addr),
    Sabme(Sabme, /* peer */ Addr),
    Dm(Dm),
    Rr(Rr, /* command */ bool),
    Rnr(Rnr),
    Ui(Ui, /* command */ bool),
    Disc(Disc),
    Iframe(Iframe, /* command */ bool),
    Ua(Ua),
    Frmr(Frmr),
    Rej(Rej),
    Srej(Srej),
    Test(Test),
    Xid(Xid),
}

/// Return events, that the state machine wants to tell the world.
///
/// IOW this excludes state changes, since only the state code needs to know
/// about that.
#[derive(Debug, PartialEq)]
pub enum ReturnEvent {
    Packet(Packet),
    DlError(DlError),
    Data(Res),
}

impl ReturnEvent {
    /// Serialize a return event.
    ///
    /// TODO: Not very clean. Only packets can serialize. Other return events
    /// return None.
    pub fn serialize(&self, ext: bool) -> Option<Vec<u8>> {
        match self {
            ReturnEvent::Packet(p) => Some(p.serialize(ext)),
            ReturnEvent::DlError(e) => {
                eprintln!("TODO: DLERROR: {e}");
                None
            }
            ReturnEvent::Data(d) => {
                debug!("Data received: {d:?}");
                None
            }
        }
    }
}

/// DLErrors (C4.3, page 81)
///
/// Error codes of all kinds.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum DlError {
    A,
    B,
    C,
    D,
    E,
    F,
    G,
    H,
    I,
    J,
    K,
    L,
    M,
    N,
    O,
    P,
    Q,
    R,
    S,
    T,
    U,
    V,
}

// Page 81.
impl std::fmt::Display for DlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}",
            match self {
                DlError::A => "A: F=1 received but P=1 not outstanding",
                DlError::B => "B: Unexpected DM with F=1 in states 3,4,5",
                DlError::C => "C: Unexpected UA in states 3 (Connected), 4 (TimerRecovery), 5 (Awaiting v2.2 Connection)",
                DlError::D => "D: UA received without F=1 when SABM or DISC was sent P=1",
                DlError::E => "E: DM received in states 3 (Connected), 4 (TimerRecovery), 5 (Awaiting v2.2 Connection)",

                DlError::F => "F: Data link reset; i.e., SABM received in state 3 (Connected), 4 (TimerRecovery), 5 (Awaiting v2.2 Connection)",
                // Spec bug: Undocumented.
                DlError::G => "G: Connection timed out",
                // Spec bug: Undocumented.
                DlError::H => "H: Undocumented. May mean connection timed out while disconnecting",
                DlError::I => "I: N2 timeouts; unacknowledged data",
                DlError::J => "J: N(r) sequence error",
                // Spec bug: Undocumented.
                DlError::K => "K: Undocumented. May mean unexpected frame received",
                DlError::L => "L: Control field invalid or not implemented",
                DlError::M => "M: Information field was received in a U- or S-type frame",
                DlError::N => "N: Length of frame incorrect for frame type",
                DlError::O => "O: I frame exceeded maximum allowed length",
                DlError::P => "P: N(s) out of the window",
                DlError::Q => "Q: UI response received, or UI command with P=1 received",
                DlError::R => "R: UI frame exceeded maximum allowed length",
                DlError::S => "S: I response received",
                DlError::T => "T: N2 timeout; no response to enquiry",
                DlError::U => "U: N2 timeouts; extended pere busy condition",
                DlError::V => "V: No DL machines available to establish connection",
            }
        )
    }
}

/// Actions are like ReturnEvent, except packets are separated.
///
/// Basically anything the state machine wants to do, aside from
/// modifying the `Data` struct, is to produce "Actions".
///
/// TODO: Terminology here is not very great.
pub enum Action {
    State(Box<dyn State>),
    DlError(DlError),
    SendUa(bool),
    SendRr(/* poll */ bool, u8, /* command */ bool),
    SendRnr(/* poll */ bool, u8, /* command */ bool),
    SendDisc(bool),
    SendIframe(Iframe),
    SendDm(bool),
    SendSabm(bool),
    Deliver(Vec<u8>),
    EOF,
}

// Spec says 3s.
const DEFAULT_SRT: std::time::Duration = std::time::Duration::from_secs(3);

const DEFAULT_MTU: usize = 200;

// Output buffer size is kept in RAM, so should not grow unbounded.
//
// At the expected speeds, 100MB is way more than what we should expect to
// send in any connection.
const MAX_OBUF_SIZE: usize = 100_000_000;

// TODO: what is the default?
const DEFAULT_T3V: std::time::Duration = std::time::Duration::from_secs(3);

// Max retry count.
const DEFAULT_N2: u8 = 3;

/// Timer object.
///
/// There are two timers, T1 and T3 (4.4.5, page 30).
#[derive(Debug)]
pub struct Timer {
    running: bool,
    expiry: std::time::Instant,
}

impl Default for Timer {
    fn default() -> Self {
        Self {
            running: false,
            expiry: std::time::Instant::now(),
        }
    }
}

impl Timer {
    /// Start timer.
    ///
    /// Called by the state machine.
    fn start(&mut self, v: std::time::Duration) {
        self.expiry = std::time::Instant::now() + v;
        self.running = true;
    }

    /// Return None if timer is not running.
    ///
    /// Returns true if it's expired, alse false.
    pub fn is_expired(&self) -> Option<bool> {
        if !self.running {
            return None;
        }
        Some(std::time::Instant::now() > self.expiry)
    }

    fn remaining(&self) -> Option<std::time::Duration> {
        if !self.running {
            return None;
        }
        Some(
            self.expiry
                .saturating_duration_since(std::time::Instant::now()),
        )
    }

    /// Stop timer.
    ///
    /// Called by the state machine.
    fn stop(&mut self) {
        self.running = false;
    }

    /// Restart timer.
    ///
    /// Called by the state machine.
    ///
    /// TODO: the spec doesn't say what the difference is between "start"
    /// and "restart". Maybe there's no difference?
    fn restart(&mut self, v: std::time::Duration) {
        self.start(v);
    }
}

/// Connection (or socket, if you will) extra data.
///
/// The state object only carries the state itself. Further data is in this
/// object.
#[derive(Debug)]
pub struct Data {
    pub(crate) me: Addr,

    pub(crate) peer: Option<Addr>,
    // TODO: double check all types.
    /// True if this client initiated the connection via SABM(E).
    ///
    /// C4.3, page 82.
    layer3_initiated: bool,

    /// T1 timer - pending ACK.
    /// 4.4.5.1, page 30.
    ///
    /// When a packet expecting a reply is sent, such as IFRAME (expecting RR or
    /// a returning IFRAME with NR), T1 is started (unless already running).
    ///
    /// T1 stops if a the last sent IFRAME is acknowledged.
    /// T1 is also used to send another SABM(E) if no UA or DM is received.
    ///
    /// If T1 expires, it initiates a retransmit.
    t1: Timer,

    /// T3 timer - Connection idle timer. (4.4.5.2, page 30)
    ///
    /// When no data is pending ACK, T3 is running. If it expires, it'll trigger
    /// RR/RNR, to probe.
    t3: Timer,
    t3v: std::time::Duration, // TODO: is this where the init value should be?

    /// Send state variable.
    ///
    /// This is the sequence number of the next frame that this node will send,
    /// in the NS field.
    ///
    /// In TCP this counts bytes, but this is packets. Value is kept at mod 8
    /// or 128 at all times.
    vs: u8,

    /// Acknowledge state variable.
    ///
    /// This is the most recent sequence number that the remote end
    /// has reported seeing.
    va: u8,

    /// Receive state variable.
    ///
    /// This is the sequence number of the next expected frame to receive
    /// from the remote end.
    vr: u8,

    /// Default SRT.
    ///
    /// SRT should be smoothed round trip time, but it needs an initial value.
    pub(crate) srt_default: std::time::Duration,

    /// Smoothed round trip time.
    ///
    /// TODO: Don't just keep this fixed.
    srt: std::time::Duration,

    /// Next value for T1; default initial value is initial value of SRT.
    t1v: std::time::Duration,

    /// Max packet size.
    ///
    /// Normally like 200 bytes. And setting it too large tends to cause
    /// some implementations to crash.
    n1: usize,

    /// Max retries.
    ///
    /// After T1 timer expires this many times, the connection attempt
    /// (SABM(E)) or connection (other frames) is aborted.
    n2: u8,

    /// Current retry counter.
    ///
    /// The current value counting towards N2.
    rc: u8,

    /// Either 8 or 128, depending on EXTSEQ.
    modulus: u8,

    /// Remote end is busy, and canet receive frames.
    /// Page 82.
    peer_receiver_busy: bool,

    /// A REJ has been sent to the remote end.
    reject_exception: bool,

    /// We are currently waiting for an incoming connection.
    ///
    /// This is false for outgoing connections, and we will not accept SABM(E)
    /// during Disconnected.
    ///
    /// In a modern spec, able to establish and not would be separate states.
    able_to_establish: bool,

    /// An SREJ has been sent to the remote end.
    ///
    /// TODO: this counts outstanding SREJs?
    sreject_exception: u32,

    /// We are busy.
    ///
    /// TODO: check if we'd ever actually set this to true. The receive window
    /// is so small that the NR/NS will wrap around way before we get "full".
    own_receiver_busy: bool,

    /// ACK, like RR, RNR, or IFRAME, pending.
    acknowledge_pending: bool,

    /// This implementation doesn't yet implement SREJ, so this
    /// is always falso for now.
    srej_enabled: bool,

    /// Maximum number of iframes outstanding.
    ///
    /// This is at most 7 (mod-8), or 127 (extseq, mod-128).
    ///
    /// This is a bit of a tunable value, especially if SREJ is not supported
    /// for the connection. Higher value means fewer bigger bursts of packets,
    /// but makes retransmissions worse. It also hogs the transmitter for other
    /// users.
    k: u8,

    // TODO: not the right type. Should be VecDeque<u8> or VecDeque<Iframe>
    //
    // TODO: this is not currently used, but should be. Either as is, or
    // a byte queue maximizing packet size.
    iframe_queue: Vec<Vec<u8>>,

    /// Output buffer of application payload bytes.
    ///
    /// This will be chopped up into frames when sequence numbers and
    /// transmitter business allows.
    obuf: VecDeque<u8>,

    /// MTU for this connection.
    mtu: usize,

    /// When an IFRAME is sent out, it's stared in this queue, until it's been
    /// acked. When a resend is required, it's sent from here.
    iframe_resend_queue: VecDeque<Iframe>,
}

impl Data {
    /// Create new Data with the specified address being the local one.
    pub fn new(me: Addr) -> Self {
        Self {
            me,
            peer: None,
            n1: 65000, // Max number of octets in the information field of a frame.
            layer3_initiated: false,
            t1: Timer::default(),
            t3: Timer::default(),
            vs: 0,
            va: 0,
            vr: 0,
            srt_default: DEFAULT_SRT,
            srt: DEFAULT_SRT,
            t1v: DEFAULT_SRT,
            t3v: DEFAULT_T3V,
            n2: DEFAULT_N2,
            rc: 0,
            k: 7,
            modulus: 8,
            peer_receiver_busy: false,
            reject_exception: false,
            sreject_exception: 0,
            srej_enabled: false,
            acknowledge_pending: false,
            own_receiver_busy: false,
            iframe_queue: Vec::new(),
            mtu: DEFAULT_MTU,
            obuf: VecDeque::new(),
            iframe_resend_queue: VecDeque::new(),
            able_to_establish: false,
        }
    }

    /// Return true if using 128 modulus.
    #[must_use]
    pub fn ext(&self) -> bool {
        self.modulus == 128
    }

    /// Return true if T1 (retry) has expired.
    #[must_use]
    pub fn t1_expired(&self) -> bool {
        self.t1.is_expired().unwrap_or(false)
    }

    /// Return true if T3 (idle timer) has expired.
    #[must_use]
    pub fn t3_expired(&self) -> bool {
        self.t3.is_expired().unwrap_or(false)
    }

    /// Return list of expired timers.
    #[must_use]
    pub fn active_timers(&self) -> Vec<Event> {
        let mut ret = Vec::new();
        if self.t1_expired() {
            ret.push(Event::T1);
        }
        if self.t3_expired() {
            ret.push(Event::T3);
        }
        ret
    }

    /// Return time until next timer expires, or None if no timer is currently
    /// running.
    #[must_use]
    pub fn next_timer_remaining(&self) -> Option<std::time::Duration> {
        match (self.t1.remaining(), self.t3.remaining()) {
            (Some(t1), Some(t3)) => Some(std::cmp::min(t1, t3)),
            (None, Some(t)) => Some(t),
            (Some(t), None) => Some(t),
            (None, None) => None,
        }
    }

    /// Do something with a received UI frame.
    ///
    /// Unnumbered information is pretty uninteresting here, since this crate
    /// handles connected mode.
    ///
    /// But we should probably add some UI support. It wouldn't be much code.
    ///
    /// Page 108.
    #[must_use]
    fn ui_check(&self, command: bool, len: usize) -> Vec<Action> {
        if !command {
            // Spec bug: error Q says this is also for UI frames with Poll set.
            //
            // But 4.3.3.6 says command+poll is just fine, and should just trigger
            // DM.
            //
            // So probably the code as-is, is correct, and the Q error message
            // should be changed.
            return vec![Action::DlError(DlError::Q)];
        }
        if len > self.n1 {
            return vec![Action::DlError(DlError::K)];
        }
        debug!("DL-UNIT_DATA indication");
        vec![]
    }

    /// NR error recovery.
    ///
    /// A received packet is trying to ACK a sequence number outside of what's
    /// currently in flight, that's an error, and the connection is terminated.
    ///
    /// Page 106.
    #[must_use]
    fn nr_error_recovery(&mut self) -> Vec<Action> {
        self.layer3_initiated = false;
        vec![Action::DlError(DlError::J), self.establish_data_link()]
    }

    /// Check need for response.
    ///
    /// If a packet is a command, and has the poll bit set, then it demands
    /// a response. I guess in theory this could be an IFRAME, if there's
    /// outstanding data. But the state diagram says to send an RR.
    ///
    /// Page 108, and 6.1.2 and 6.2 on pages 35-36.
    #[must_use]
    fn check_need_for_response(&mut self, command: bool, pf: bool) -> Vec<Action> {
        match (command, pf) {
            // A command with poll set demands a response with fin set.
            (true, true) => vec![self.enquiry_response(true)],

            // I believe that this means the state is currently Connected,
            // and therefore we're not waiting for a response.
            (false, true) => vec![Action::DlError(DlError::A)],

            // If it's not a command, or a command but no response required,
            // then no response needed.
            (_, _) => vec![],
        }
    }

    /// Respond to the other end demanding a sequence number report.
    ///
    /// Bug in 1998 spec, fixed in the 2017 doc:
    /// This function is literally called "response", but the spec says
    /// "RR command". I think not.  It breaks against the Linux implementation
    /// if sending a command, since the kernel never gets answered.
    ///
    /// The kernel (M0THC-2) keeps asking (P), but by following the spec keeps
    /// asking right back.
    ///
    ///  9584 18.543153318      M0THC-2 → M0THC-1      AX.25 16 S P, func=RR, N(R)=1
    ///  9585 18.546108006      M0THC-1 → M0THC-2      AX.25 16 S P, func=RR, N(R)=5
    ///  9586 18.546117747      M0THC-2 → M0THC-1      AX.25 16 S F, func=RR, N(R)=1
    ///
    /// Repeats until Linux kernel gives up and sends DM, closing the connection.
    ///
    /// In the parts currently implemented, `pf` is always set to `true`.
    ///
    /// Page 106.
    #[must_use]
    fn enquiry_response(&mut self, f: bool) -> Action {
        self.acknowledge_pending = false;
        // TODO: 2017 spec has a bit more complex diagram here. Some of it is
        // correct, but other stuff I'm not so sure of.
        //
        // Most of it is SREJ related, but it also says to send RR instead of
        // RNR if not `F==1 && (RR || RNR || I)`.
        if self.own_receiver_busy {
            // 1998 spec doesn't say, but 2017 spec says "Response".
            Action::SendRnr(f, self.vr, /* command */ false)
        } else {
            // Spec says commmand, which is wrong.
            Action::SendRr(f, self.vr, /* command */ false)
        }
    }

    /// Retransmit the resend queue.
    ///
    /// If the remote acks something other than our latest packet, then
    /// send everything unacked.
    ///
    /// TODO: Is this a good idea? This seems like it's a bit over eager in
    /// retransmitting.
    ///
    /// Page 107.
    #[must_use]
    fn invoke_retransmission(&mut self, _nr: u8) -> Vec<Action> {
        self.iframe_resend_queue
            .iter()
            .map(|i| Action::SendIframe(i.clone()))
            .collect()
    }

    /// Select a new T1 value based off of the roundtrip time.
    ///
    /// TODO: actually implement this. Maybe the algorithm in the spec, maybe
    /// something better.
    ///
    /// TODO: Is this supposed to set only SRT, or also T1V?
    ///
    /// Page 109.
    fn select_t1_value(&mut self) {
        if self.rc == 0 {
            // TODO: the real formula is stranger.
            self.srt = self.srt_default;
        } else if self.t1_expired() {
            // 1998 spec says:
            // self.srt = self.srt * (2 ** (rc + 1));

            // 2017 spec formula.
            // It's unclear what unit `rc` is supposed to be. It's retry
            // counter. I'll assume seconds, to millisecond resolution.
            // SRT = RC / 4 + SRT*2
            let t = std::time::Duration::from_millis(self.rc as u64 * 250);
            self.srt = t + self.srt + self.srt;
        }
    }

    /// Ask remote end if they're there, what they heard last.
    ///
    /// This is when T1 or T3 expires.
    ///
    /// Page 106.
    #[must_use]
    fn transmit_enquiry(&mut self) -> Action {
        self.acknowledge_pending = false;
        self.t1.start(self.t1v); // TODO: what timer value?
        if self.own_receiver_busy {
            Action::SendRnr(/* poll */ true, self.vr, /* command */ true)
        } else {
            Action::SendRr(/* poll */ true, self.vr, /* command */ true)
        }
    }

    /// When RR is received, incorporate any new info, and potentially
    /// wait for more RRs.
    ///
    /// Page 107.
    #[must_use]
    fn check_iframe_acked(&mut self, nr: u8) -> Vec<Action> {
        // Typo in spec. Says "peer busy".
        if self.peer_receiver_busy {
            // 1998 spec says start T3, 2017 spec says stop it.
            // It doesn't make much sense to run both T1 and T3, so let's go
            // with 2017.
            self.t3.stop();
            if !self.t1.running {
                self.t1.start(self.srt); // srt or t1v?
            }
            self.update_ack(nr)
        } else if nr == self.vs {
            self.t1.stop();
            self.t3.start(self.t3v);
            self.select_t1_value();
            self.update_ack(nr)
        } else if nr != self.va {
            // 1998 spec says "restart", 2017 spec just "start". They probably
            // mean the same thing, right?
            self.t1.restart(self.srt);
            self.update_ack(nr)
        } else {
            vec![]
        }
    }

    /// Update state based on an an ACK being received.
    ///
    /// As ACK moves forward, the iframe resend queue can be pruned.
    ///
    /// In the spec this is just `va <- nr`, which hides the complexity.
    #[must_use]
    fn update_ack(&mut self, nr: u8) -> Vec<Action> {
        // dbg!(self.va, nr);
        // debug!("Updating ack to {} {}", self.va, nr);
        while self.va != nr {
            assert!(!self.iframe_resend_queue.is_empty());
            self.iframe_resend_queue.pop_front();
            self.va = (self.va + 1) % self.modulus;
        }
        self.flush()
    }

    /// Clear iframe queue.
    ///
    /// This probably means connection shutdown.
    fn clear_iframe_queue(&mut self) {
        self.iframe_queue.clear();
        self.iframe_resend_queue.clear();
    }

    /// Clear exception conditions as a new connection is established.
    fn clear_exception_conditions(&mut self) {
        self.peer_receiver_busy = false;
        self.reject_exception = false;
        self.own_receiver_busy = false;
        self.acknowledge_pending = false;

        // The following added in 2017 spec.
        self.sreject_exception = 0;

        // Huh? Clearing the iframe queue inside a subroutine called "clear
        // exception conditions"? That doesn't seem right.
        //
        // This is new in the 2017 spec.
        //
        // I'm going to leave it here because when exception conditions are
        // unconditionally cleared, it's because a connection was just reset in
        // one way or another.
        self.iframe_queue.clear();
    }

    /// Establish data link.
    ///
    /// Some connection initialization.
    ///
    /// Page 106 & "establish extended data link" on page 109.
    #[must_use]
    fn establish_data_link(&mut self) -> Action {
        self.clear_exception_conditions();

        // 1998 spec says to set rc to 0, 2017 says 1.
        // Yeah I think 1 is right.
        self.rc = 1;
        self.t3.stop();
        // Again 1998 spec says restart, 2017 says start.
        self.t1.restart(self.srt); // TODO: srt or t1v?

        // SendSabm actually sends SABME if modulus is 128.
        Action::SendSabm(true)
    }

    /// Set values for extended sequence number connection.
    ///
    /// Page 109.
    fn set_version_2_2(&mut self) {
        // TODO: set half duplex SREJ
        self.modulus = 128;
        // TODO: n1r = 2048

        // Spec bug: Spec says `kr`. Surely it means `k`?
        self.k = 32;

        // TODO: self.t2.set(3000);
        self.n2 = 10;
    }

    /// Set values for mod-8 connections.
    ///
    /// Page 109.
    fn set_version_2(&mut self) {
        self.modulus = 8;
        // TODO: n1r = 2048

        // Spec bug: Spec says `kr`. Surely it means `k`?
        self.k = 4;

        // TODO: self.t2.set(3000);
        self.n2 = 10;
    }

    // If sequence numbers allow, write as many packets as possible.
    //
    // Page 92, "I frame pops off queue".
    #[must_use]
    fn flush(&mut self) -> Vec<Action> {
        if self.peer_receiver_busy {
            return vec![];
        }
        let mut act = Vec::new();
        loop {
            if self.obuf.is_empty() {
                break;
            }
            if self.vs == (self.va + self.k) % self.modulus {
                debug!(
                    "tx window full with more data ({} bytes) to send!",
                    self.obuf.len()
                );
                break;
            }
            let payload = self
                .obuf
                .drain(..std::cmp::min(self.mtu, self.obuf.len()))
                .collect::<Vec<_>>();
            let ns = self.vs;
            self.vs = (self.vs + 1) % self.modulus;
            self.acknowledge_pending = false;
            if self.t1.running {
                self.t3.stop();
                self.t1.start(self.srt);
            }
            let i = Iframe {
                ns,
                nr: self.vr,
                poll: false,
                pid: 0xF0,
                payload,
            };
            self.iframe_resend_queue.push_back(i.clone());
            act.push(Action::SendIframe(i));
        }
        act
    }
}

/// State machine for an AX.25 connection.
///
/// Not all events are implemented in all states, but enough.
///
/// TODO: remove default implementations, to make the "default noop" more
/// deliberate.
pub trait State {
    fn name(&self) -> String;
    fn is_state_connected(&self) -> bool {
        false
    }
    fn is_state_disconnected(&self) -> bool {
        false
    }

    /// User initiates a new connection.
    #[must_use]
    fn connect(&self, _data: &mut Data, _addr: &Addr, _ext: bool) -> Vec<Action> {
        eprintln!("TODO: unexpected DLConnect");
        vec![]
    }

    /// User initiates disconnection.
    #[must_use]
    fn disconnect(&self, _data: &mut Data) -> Vec<Action> {
        eprintln!("TODO: unexpected DLDisconnect in state {}", self.name());
        vec![]
    }

    /// User initiates sending data on a connection.
    #[must_use]
    fn data(&self, _data: &mut Data, _payload: &[u8]) -> Vec<Action> {
        eprintln!("writing data while not connected!");
        vec![]
    }

    /// Timer T1 (pending ack) expires.
    #[must_use]
    fn t1(&self, _data: &mut Data) -> Vec<Action> {
        eprintln!("TODO: unexpected T1 expire");
        vec![]
    }

    /// Timer T3 (connection keepalive) expires.
    #[must_use]
    fn t3(&self, _data: &mut Data) -> Vec<Action> {
        eprintln!("TODO: unexpected T3 expire");
        vec![]
    }

    /// RR received from peer.
    #[must_use]
    fn rr(&self, _data: &mut Data, _packet: &Rr, _command: bool) -> Vec<Action> {
        eprintln!("TODO: unexpected RR");
        vec![]
    }

    /// REJ received from peer.
    #[must_use]
    fn rej(&self, _data: &mut Data, _packet: &Rej) -> Vec<Action> {
        eprintln!("TODO: unexpected REJ");
        vec![]
    }

    /// XID received from peer.
    #[must_use]
    fn xid(&self, _data: &mut Data, _packet: &Xid) -> Vec<Action> {
        eprintln!("TODO: unexpected XID");
        vec![]
    }

    /// TEST received from peer.
    #[must_use]
    fn test(&self, _data: &mut Data, _packet: &Test) -> Vec<Action> {
        eprintln!("TODO: unexpected TEST");
        vec![]
    }

    /// SREJ received from peer.
    #[must_use]
    fn srej(&self, _data: &mut Data, _packet: &Srej) -> Vec<Action> {
        eprintln!("TODO: unexpected SREJ");
        vec![]
    }

    /// FRMR received from peer.
    ///
    /// FRMR is deprecated, so we should probably never see this.
    #[must_use]
    fn frmr(&self, _data: &mut Data) -> Vec<Action> {
        eprintln!("TODO: unexpected FRMR");
        vec![]
    }

    /// RNR received from peer.
    #[must_use]
    fn rnr(&self, _data: &mut Data, _packet: &Rnr) -> Vec<Action> {
        eprintln!("TODO: unexpected RNR");
        vec![]
    }

    /// SABM received from peer.
    #[must_use]
    fn sabm(&self, _data: &mut Data, _src: &Addr, _packet: &Sabm) -> Vec<Action> {
        eprintln!("TODO: unexpected SABM");
        vec![]
    }

    /// SABME received from peer.
    #[must_use]
    fn sabme(&self, _data: &mut Data, _src: &Addr, _packet: &Sabme) -> Vec<Action> {
        eprintln!("TODO: unexpected SABME");
        vec![]
    }

    /// IFRAME received from peer.
    #[must_use]
    fn iframe(&self, _data: &mut Data, _packet: &Iframe, _cr: bool) -> Vec<Action> {
        eprintln!("TODO; unexpected iframe");
        vec![]
    }

    /// UI received from peer.
    #[must_use]
    fn ui(&self, _data: &mut Data, _cr: bool, _packet: &Ui) -> Vec<Action> {
        vec![]
    }

    /// UA received from peer.
    #[must_use]
    fn ua(&self, _data: &mut Data, _packet: &Ua) -> Vec<Action> {
        eprintln!("TODO; unexpected UA");
        vec![]
    }

    /// DM received from peer.
    #[must_use]
    fn dm(&self, _data: &mut Data, _packet: &Dm) -> Vec<Action> {
        eprintln!("TODO: unexpected DM");
        vec![]
    }

    /// DISC received from peer.
    #[must_use]
    fn disc(&self, _data: &mut Data, _packet: &Disc) -> Vec<Action> {
        eprintln!("TODO: unexpected DISC");
        vec![]
    }
}

/// Disconnected state.
///
/// I think this is fully implemented for AX.25 2.0. No SABME yet, though.
///
/// This is a state diagram for a connection. Any non-listening socket
/// should in theory cause `SendDm(p.poll)`, but out of scope.
struct Disconnected {}
impl Disconnected {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }

    // Page 85.
    #[must_use]
    fn sabm_and_sabme(&self, data: &mut Data, src: Addr, poll: bool) -> Vec<Action> {
        debug!("DL-Connect indication");
        if !data.able_to_establish {
            return vec![Action::SendDm(poll)];
        }
        data.clear_exception_conditions();
        data.vs = 0;
        data.va = 0;
        data.vr = 0;
        data.srt = data.srt_default;
        data.t1v = data.srt + data.srt;
        data.t3.start(data.t3v);
        data.rc = 0;
        data.peer = Some(src);
        vec![
            Action::SendUa(poll),
            Action::State(Box::new(Connected::new(ConnectedState::Connected))),
        ]
    }
}

// Page 84-85.
//
// "All other commands" should generate a DM. Does it mean all other incoming packets?
// Other than that, this state should be complete.
impl State for Disconnected {
    fn name(&self) -> String {
        "Disconnected".to_string()
    }

    fn is_state_disconnected(&self) -> bool {
        true
    }

    // Page 85.
    fn connect(&self, data: &mut Data, addr: &Addr, ext: bool) -> Vec<Action> {
        data.modulus = match ext {
            true => 128,
            false => 8,
        };
        // It says "SAT" in the PDF, but surely means SRT?
        data.peer = Some(addr.clone());
        data.srt = data.srt_default;
        data.t1v = 2 * data.srt;
        data.layer3_initiated = true;
        vec![
            Action::State(Box::new(AwaitingConnection::new())),
            data.establish_data_link(),
        ]
    }

    // Page 84.
    fn disconnect(&self, _data: &mut Data) -> Vec<Action> {
        eprintln!("Disconnect while already disconnected");
        vec![]
    }

    // Page 84.
    fn ui(&self, data: &mut Data, cr: bool, packet: &Ui) -> Vec<Action> {
        let mut ret = data.ui_check(cr, packet.payload.len());
        if packet.push {
            ret.push(Action::SendDm(true));
        }
        ret
    }

    // Page 85.
    fn sabm(&self, data: &mut Data, src: &Addr, sabm: &Sabm) -> Vec<Action> {
        data.set_version_2();
        self.sabm_and_sabme(data, src.clone(), sabm.poll)
    }

    // Page 85.
    fn sabme(&self, data: &mut Data, src: &Addr, packet: &Sabme) -> Vec<Action> {
        data.set_version_2_2();
        self.sabm_and_sabme(data, src.clone(), packet.poll)
    }

    // Page 84.
    fn dm(&self, _data: &mut Data, _packet: &Dm) -> Vec<Action> {
        vec![]
    }

    // Page 84.
    fn ua(&self, _data: &mut Data, _packet: &Ua) -> Vec<Action> {
        vec![Action::DlError(DlError::C), Action::DlError(DlError::D)]
    }

    // Page 84.
    fn disc(&self, _data: &mut Data, packet: &Disc) -> Vec<Action> {
        vec![Action::SendDm(packet.poll)]
    }
}

// AwaitingConnection means a SABM(E) has been sent, and we are waiting for the
// UA.
struct AwaitingConnection {}

impl AwaitingConnection {
    #[must_use]
    fn new() -> Self {
        Self {}
    }
}

impl State for AwaitingConnection {
    fn name(&self) -> String {
        "AwaitingConnection".to_string()
    }

    // Page 88.
    fn t1(&self, data: &mut Data) -> Vec<Action> {
        eprintln!("t1 expired while connecting, retrying");
        if data.rc == data.n2 {
            data.clear_iframe_queue();
            vec![
                // Typo in spec: G, not g.
                Action::DlError(DlError::G),
                Action::State(Box::new(Disconnected::new())),
            ]
        } else {
            data.rc += 1;
            data.select_t1_value();
            data.t1.start(data.srt);
            vec![Action::SendSabm(true)]
        }
    }

    // Page 88.
    fn ua(&self, data: &mut Data, packet: &Ua) -> Vec<Action> {
        let f = packet.poll;
        if !f {
            return vec![Action::DlError(DlError::D)];
        }
        if data.layer3_initiated {
            debug!("DL-CONNECT CONFIRM");
        } else if data.vs != data.va {
            // 1998 spec:
            // We're awaiting a connection confirmation, but vs!=va? What does
            // that mean?
            //
            // If we're getting an UA after remote end has already acked
            // some packets, what does that even mean?
            //
            //   data.iframe_queue.clear();
            //   debug!("DL-CONNECT indiciation"); // huh?
            //
            // 2017 spec;
            // I still wonder what it means, what the intention is.
            //
            // In addition, there's a bug in the 2017 spec. This path says to
            // start T1, then immediately stop it again.
            data.srt = data.srt_default;
            data.t1v = data.srt + data.srt;
            debug!("DL-CONNECT CONFIRM, vs!=va");
            warn!("Strange state entered: UA received while vs != va");
        }
        data.t1.stop();

        // 1998 spec says "stop T3".
        // 2017 spec says "start T3" (page 89), which makes much more sense.
        data.t3.start(data.t3v);

        data.vs = 0;
        data.va = 0;
        data.vr = 0;
        data.select_t1_value();
        vec![Action::State(Box::new(Connected::new(
            ConnectedState::Connected,
        )))]
    }

    // Page 86.
    fn sabm(&self, _data: &mut Data, _src: &Addr, packet: &Sabm) -> Vec<Action> {
        vec![Action::SendUa(packet.poll)]
    }

    // Page 88.
    fn sabme(&self, _data: &mut Data, _src: &Addr, packet: &Sabme) -> Vec<Action> {
        // TODO: This is supposed to transition to "awaiting connect 2.2".
        vec![Action::SendDm(packet.poll)]
    }
}

/// TODO: document the meaning of this state.
struct AwaitingRelease {}

impl AwaitingRelease {
    #[must_use]
    fn new() -> Self {
        Self {}
    }
}

// Starting on page 89.
impl State for AwaitingRelease {
    fn name(&self) -> String {
        "AwaitingRelease".to_string()
    }

    // Page 91.
    fn dm(&self, data: &mut Data, p: &Dm) -> Vec<Action> {
        if !p.poll {
            return vec![];
        }
        data.t1.stop();
        vec![Action::State(Box::new(Disconnected::new()))]
    }

    // Page 90.
    fn ua(&self, data: &mut Data, p: &Ua) -> Vec<Action> {
        if !p.poll {
            return vec![Action::DlError(DlError::D)];
        }
        debug!("DL-DISCONNECT confirm");
        data.t1.stop();
        vec![Action::State(Box::new(Disconnected::new()))]
    }

    // Page 91.
    fn t1(&self, data: &mut Data) -> Vec<Action> {
        if data.rc == data.n2 {
            debug!("DL-DISCONNECT confirm");
            // The spec doesn't say, but if we're going disconnected, then
            // there's no need for timers.
            data.t1.stop();
            data.t3.stop();
            return vec![
                Action::DlError(DlError::H),
                Action::State(Box::new(Disconnected::new())),
            ];
        }
        data.rc += 1;
        data.select_t1_value();
        data.t1.start(data.t1v);
        vec![Action::SendDisc(true)]
    }

    // TODO: More handlers.
}

enum ConnectedState {
    Connected,
    TimerRecovery,
}

/// TODO: document the meaning of this state.
struct Connected {
    connected_state: ConnectedState,
}

impl Connected {
    #[must_use]
    fn new(connected_state: ConnectedState) -> Self {
        Self { connected_state }
    }

    // Page 95
    #[must_use]
    fn rr_connected(&self, data: &mut Data, packet: &Rr, cr: bool) -> Vec<Action> {
        data.peer_receiver_busy = false;
        let mut act = data.check_need_for_response(cr, packet.poll);
        if !in_range(data.va, packet.nr, data.vs, data.modulus) {
            act.extend(data.nr_error_recovery());
            act.push(Action::State(Box::new(AwaitingConnection::new())));
        } else {
            act.extend(data.check_iframe_acked(packet.nr));
        }
        act
    }

    // Page 99.
    #[must_use]
    fn rr_timer_recovery(&self, data: &mut Data, packet: &Rr, cr: bool) -> Vec<Action> {
        data.peer_receiver_busy = false;
        if !cr && packet.poll {
            data.t1.stop();
            data.select_t1_value();
            if !in_range(data.va, packet.nr, data.vs, data.modulus) {
                let mut act = data.nr_error_recovery();
                act.push(Action::State(Box::new(AwaitingConnection::new())));
                return act;
            }
            let mut act = data.update_ack(packet.nr);
            if data.vs == data.va {
                data.t3.start(data.t3v);
                data.rc = 0; // Added in 2017 spec, page 95.
                act.push(Action::State(Box::new(Connected::new(
                    ConnectedState::Connected,
                ))));
            } else {
                act.extend(data.invoke_retransmission(packet.nr));

                // The following added in 2017 spec, page 95.
                data.t3.stop();
                data.t1.start(data.t1v);
                data.acknowledge_pending = true;
            }
            return act;
        }
        let mut act = Vec::new();
        // 2017 spec bug on page 95: no 'no' path from this if.
        if cr && packet.poll {
            act.push(data.enquiry_response(true));
        }
        if in_range(data.va, packet.nr, data.vs, data.modulus) {
            act.extend(data.update_ack(packet.nr));
        } else {
            act.extend(data.nr_error_recovery());
            act.push(Action::State(Box::new(AwaitingConnection::new())));
        }
        act
    }

    // Page 93 and page 99.
    fn sabm_or_sabme(&self, data: &mut Data, poll: bool) -> Vec<Action> {
        data.clear_exception_conditions();
        if data.vs != data.va {
            data.iframe_queue.clear();
            debug!("DL-Connect indication");
        }
        data.t1.stop();

        // 2017 spec says to stop both T1 and T3 in state timer recovery. That
        // can't be right, can it?
        data.t3.start(data.t3v);
        data.va = 0;
        data.vs = 0;
        data.vr = 0; // 1998 spec typos this as another vs=0.
        if let ConnectedState::Connected = self.connected_state {
            // Added in 2017 spec, but only for Connected.
            // TODO: should this be set also for TimerRecovery?
            data.rc = 0;
        }
        vec![
            Action::DlError(DlError::F),
            Action::SendUa(poll),
            Action::State(Box::new(Connected::new(ConnectedState::Connected))),
        ]
    }
}

impl State for Connected {
    fn name(&self) -> String {
        match self.connected_state {
            ConnectedState::Connected => "Connected".to_string(),
            ConnectedState::TimerRecovery => "TimerRecovery".to_string(),
        }
    }
    fn is_state_connected(&self) -> bool {
        true
    }

    // Page 92 & 98.
    fn disconnect(&self, data: &mut Data) -> Vec<Action> {
        data.clear_iframe_queue();
        data.rc = 0;
        data.t1.start(data.srt); // TODO: with what timer?
        data.t3.stop();
        vec![
            Action::SendDisc(true),
            Action::State(Box::new(AwaitingRelease::new())),
        ]
    }

    // Page 92 & 98.
    //
    // This implementation deliberately doesn't preserve the application's
    // frame boundaries.
    //
    // This seems like the right thing to do. But in the future maybe we'll
    // implement the equivalent of SEQPACKET.
    fn data(&self, data: &mut Data, payload: &[u8]) -> Vec<Action> {
        data.obuf.extend(payload);
        if data.obuf.len() > MAX_OBUF_SIZE {
            panic!(
                "TODO: handle better. Output buffer got too large. {} > {}",
                data.obuf.len(),
                MAX_OBUF_SIZE
            );
        }
        data.flush()
    }

    // Page 93.
    //
    // src is ignored, because it's presumed to already have been checked, in
    // this state.
    fn sabm(&self, data: &mut Data, _src: &Addr, packet: &Sabm) -> Vec<Action> {
        data.set_version_2();
        self.sabm_or_sabme(data, packet.poll)
    }

    // Page 93.
    //
    // src is ignored, because it's presumed to already have been checked, in
    // this state.
    fn sabme(&self, data: &mut Data, _src: &Addr, packet: &Sabme) -> Vec<Action> {
        data.set_version_2_2();
        self.sabm_or_sabme(data, packet.poll)
    }

    // Page 93 & 101.
    //
    // Done.
    fn dm(&self, data: &mut Data, _packet: &Dm) -> Vec<Action> {
        debug!("DL-DISCONNECT");
        data.clear_iframe_queue();
        data.t1.stop();
        data.t3.stop();
        vec![
            Action::DlError(DlError::E),
            Action::State(Box::new(Disconnected::new())),
        ]
    }

    // Page 93 & 100.
    //
    // Done.
    fn disc(&self, data: &mut Data, p: &Disc) -> Vec<Action> {
        data.clear_iframe_queue();
        data.t1.stop();
        data.t3.stop();
        vec![
            Action::SendUa(p.poll),
            Action::EOF,
            Action::State(Box::new(Disconnected::new())),
        ]
    }

    // Page 96 & 102.
    fn iframe(&self, data: &mut Data, p: &Iframe, command_response: bool) -> Vec<Action> {
        if !command_response {
            // 2017 spec says to DlError::O if the iframe *is* a command.
            // That's not even remotely correct, since O means packet too big.
            return vec![Action::DlError(DlError::S)];
        }
        if p.payload.len() > data.n1 {
            data.layer3_initiated = false;
            debug!("Discarding frame for being too big");
            return vec![
                data.establish_data_link(),
                Action::DlError(DlError::O),
                Action::State(Box::new(AwaitingConnection::new())),
            ];
        }
        if !in_range(data.va, p.nr, data.vs, data.modulus) {
            debug!("Discarding frame for being out of range");
            let mut acts = data.nr_error_recovery();
            acts.push(Action::State(Box::new(AwaitingConnection::new())));
            return acts;
        }
        let mut actions = vec![];
        match self.connected_state {
            ConnectedState::Connected => actions.extend(data.check_iframe_acked(p.nr)),
            ConnectedState::TimerRecovery => actions.extend(data.update_ack(p.nr)),
        }
        if data.own_receiver_busy {
            // discord (implicit)
            debug!("Discarding iframe because busy and being polled");
            if p.poll {
                actions.push(Action::SendRnr(true, data.vr, /* command */ false));
                data.acknowledge_pending = false;
            }
            return actions;
        }

        if p.ns == data.vr {
            debug!("iframe in order {}", p.ns);
            // Frame is in order.
            data.vr = (data.vr + 1) % data.modulus;
            data.reject_exception = false;
            if data.sreject_exception > 0 {
                data.sreject_exception -= 1;
            }
            actions.push(Action::Deliver(p.payload.clone()));
            // TODO: check for stored out of order frames
            while
            /* i frame stored */
            false {
                // retrieve stored vr in frame
                // Deliver
                data.vr = (data.vr + 1) % data.modulus;
            }
            if p.poll {
                actions.push(Action::SendRr(/*final*/ true, data.vr, false));
                data.acknowledge_pending = false;
                return actions;
            }
            if !data.acknowledge_pending {
                // LM seize request (?).
                data.acknowledge_pending = true;
            }
            return actions;
        }
        debug!("Iframe not in order {} {}", p.ns, data.vr);
        if data.reject_exception {
            // discard frame (implicit)
            if p.poll {
                actions.push(Action::SendRr(/*final*/ true, data.vr, false));
                data.acknowledge_pending = false;
            }
            return actions;
        }
        if !data.srej_enabled {
            // discard iframe (implicit)
            data.reject_exception = true;
            // TODO: actions.push(Action::SendRej(final=poll, data.vr)
            data.acknowledge_pending = false;
            return actions;
        }
        // TODO: save contents of iframe
        if data.sreject_exception > 0 {
            data.sreject_exception += 1;
            // TODO: actions.push(Action::SendSrej(final=false, nr=p.ns));
            data.acknowledge_pending = false;
            return actions;
        }
        // if ns > vr + 1
        // TODO: Maybe a version of if in_range(p.ns) {
        if p.ns != (data.vr + 1) % data.modulus {
            // discard iframe (implicit)
            // TODO: actions.push(Action::SendRej(p.poll, data.vr));
            data.acknowledge_pending = false;
            return actions;
        }
        data.sreject_exception += 1;
        // TODO: actions.push(Action::SendSrej(final=false, nr=data.vr));
        data.acknowledge_pending = false;
        actions
    }

    // Page 93 & 99.
    fn t1(&self, data: &mut Data) -> Vec<Action> {
        data.rc = match self.connected_state {
            ConnectedState::Connected => 1,
            ConnectedState::TimerRecovery => data.rc + 1,
        };
        if data.rc != data.n2 {
            return vec![
                data.transmit_enquiry(),
                Action::State(Box::new(Connected::new(ConnectedState::TimerRecovery))),
            ];
        }
        data.clear_iframe_queue(); // Spec says "discard" iframe queue.
        debug!("DL-DISCONNECT request");
        vec![
            Action::DlError(match (data.vs == data.va, data.peer_receiver_busy) {
                (false, _) => DlError::I,
                (true, true) => DlError::U,
                (true, false) => DlError::T,
            }),
            Action::SendDm(true), // TODO: spec (page 99) doesn't say if it should be true or false.
            Action::State(Box::new(Disconnected::new())),
        ]
    }

    // Page 93 (Connected only).
    fn t3(&self, data: &mut Data) -> Vec<Action> {
        assert!(
            matches![self.connected_state, ConnectedState::Connected],
            "T3 should not be running in TimerRecovery"
        );
        data.rc = 0;
        vec![
            Action::State(Box::new(Connected::new(ConnectedState::TimerRecovery))),
            data.transmit_enquiry(),
        ]
    }

    // Page 93 & 100.
    //
    // 2017 spec says DlError::K, which is undocumented.
    fn ua(&self, data: &mut Data, _ua: &Ua) -> Vec<Action> {
        data.layer3_initiated = false;
        vec![
            Action::DlError(DlError::C),
            data.establish_data_link(),
            Action::State(Box::new(AwaitingConnection::new())),
        ]
    }

    // Page 94 & 101.
    //
    // For TimerRecovery, see note K.
    fn frmr(&self, data: &mut Data) -> Vec<Action> {
        data.layer3_initiated = false;
        vec![
            Action::DlError(DlError::K),
            data.establish_data_link(),
            Action::State(Box::new(AwaitingConnection::new())),
        ]
    }

    // Page 94 & 100.
    fn ui(&self, data: &mut Data, cr: bool, packet: &Ui) -> Vec<Action> {
        let mut act = data.ui_check(cr, packet.payload.len());
        if packet.push {
            act.push(data.enquiry_response(true));
        }
        act
    }

    fn rr(&self, data: &mut Data, packet: &Rr, cr: bool) -> Vec<Action> {
        match self.connected_state {
            ConnectedState::Connected => self.rr_connected(data, packet, cr),
            ConnectedState::TimerRecovery => self.rr_timer_recovery(data, packet, cr),
        }
    }
}

/// Ugly range checker.
///
/// if va steps forward, will it hit nr before it hits vs?
#[must_use]
fn in_range(va: u8, nr: u8, vs: u8, modulus: u8) -> bool {
    let mut t = va;
    loop {
        if t == nr {
            return true;
        }
        if t == vs {
            return false;
        }
        t = (t + 1) % modulus;
    }
}

/// Create new state machine, starting in state `Disconnected`.
#[must_use]
pub fn new() -> Box<dyn State> {
    Box::new(Disconnected::new())
}

/// Data delivery object.
///
/// None => No data available now.
/// EOF => Connection is closed.
/// Some(_) => Some data, here you go.
///
/// TODO: poorly named.
#[derive(Debug, PartialEq)]
pub enum Res {
    None,
    EOF,
    Some(Vec<u8>),
}

/// Handle an incoming state, by shoving it through the state machine.
///
/// A set of return events and possibly a new state is returned..
#[must_use]
pub fn handle(
    state: &dyn State,
    data: &mut Data,
    packet: &Event,
) -> (Option<Box<dyn State>>, Vec<ReturnEvent>) {
    let actions = match packet {
        Event::Connect(addr, ext) => state.connect(data, addr, *ext),
        Event::Disconnect => state.disconnect(data),
        Event::Data(payload) => state.data(data, payload),
        Event::T1 => state.t1(data),
        Event::T3 => state.t3(data),
        Event::Sabm(p, src) => state.sabm(data, src, p),
        Event::Sabme(p, src) => state.sabme(data, src, p),
        Event::Dm(dm) => state.dm(data, dm),
        Event::Ui(p, cr) => state.ui(data, *cr, p),
        Event::Disc(p) => state.disc(data, p),
        Event::Iframe(p, command_response) => state.iframe(data, p, *command_response),
        Event::Ua(p) => state.ua(data, p),
        Event::Rr(p, command) => state.rr(data, p, *command),
        Event::Rnr(p) => state.rnr(data, p),
        Event::Frmr(_) => state.frmr(data),
        Event::Rej(p) => state.rej(data, p),
        Event::Srej(p) => state.srej(data, p),
        Event::Xid(p) => state.xid(data, p),
        Event::Test(p) => state.test(data, p),
    };
    let mut ret = Vec::new();

    // Save non-state actions.
    for act in &actions {
        use Action::*;
        match act {
            Action::State(_) => {} // Ignore state change at this stage.
            DlError(code) => ret.push(ReturnEvent::DlError(*code)),
            SendIframe(iframe) => ret.push(ReturnEvent::Packet(Packet {
                src: data.me.clone(),
                dst: data.peer.clone().unwrap().clone(),
                command_response: true,     // TODO: what value?
                command_response_la: false, // TODO: same
                digipeater: vec![],
                rr_dist1: false,
                rr_extseq: false,
                packet_type: PacketType::Iframe(iframe.clone()),
            })),
            SendDisc(poll) => ret.push(ReturnEvent::Packet(Packet {
                src: data.me.clone(),
                dst: data.peer.clone().unwrap().clone(),
                command_response: true,     // TODO: what value?
                command_response_la: false, // TODO: same
                digipeater: vec![],
                rr_dist1: false,
                rr_extseq: false,
                packet_type: PacketType::Disc(Disc { poll: *poll }),
            })),
            SendUa(poll) => ret.push(ReturnEvent::Packet(Packet {
                src: data.me.clone(),
                dst: data.peer.clone().unwrap().clone(),
                command_response: true,     // TODO: what value?
                command_response_la: false, // TODO: same
                digipeater: vec![],
                rr_dist1: false,
                rr_extseq: false,
                packet_type: PacketType::Ua(Ua { poll: *poll }),
            })),
            SendRr(poll, nr, command) => ret.push(ReturnEvent::Packet(Packet {
                src: data.me.clone(),
                dst: data.peer.clone().unwrap().clone(),
                command_response: *command,
                command_response_la: !*command,
                digipeater: vec![],
                rr_dist1: false,
                rr_extseq: false,
                packet_type: PacketType::Rr(Rr {
                    poll: *poll,
                    nr: *nr,
                }),
            })),
            SendRnr(poll, nr, cr) => ret.push(ReturnEvent::Packet(Packet {
                src: data.me.clone(),
                dst: data.peer.clone().unwrap().clone(),
                command_response: *cr,
                command_response_la: !*cr,
                digipeater: vec![],
                rr_dist1: false,
                rr_extseq: false,
                packet_type: PacketType::Rnr(Rnr {
                    poll: *poll,
                    nr: *nr,
                }),
            })),
            SendDm(poll) => ret.push(ReturnEvent::Packet(Packet {
                src: data.me.clone(),
                dst: data.peer.clone().unwrap().clone(),
                command_response: true,     // TODO: what value?
                command_response_la: false, // TODO: same
                digipeater: vec![],
                rr_dist1: false,
                rr_extseq: false,
                packet_type: PacketType::Dm(Dm { poll: *poll }),
            })),
            SendSabm(poll) => ret.push(ReturnEvent::Packet(Packet {
                src: data.me.clone(),
                dst: data.peer.clone().unwrap().clone(),
                command_response: true,     // TODO: what value?
                command_response_la: false, // TODO: same
                digipeater: vec![],
                rr_dist1: false,
                rr_extseq: false,
                packet_type: PacketType::Sabm(Sabm { poll: *poll }),
            })),
            // TODO: can we avoid the copy?
            Deliver(p) => ret.push(ReturnEvent::Data(Res::Some(p.to_vec()))),
            EOF => ret.push(ReturnEvent::Data(Res::EOF)),
        }
    }
    for act in actions {
        // Non-statechange actions handled above.
        if let Action::State(new_state) = act {
            return (Some(new_state), ret);
        }
    }
    (None, ret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_all(want: &[ReturnEvent], got: &[ReturnEvent], more: &str) {
        for w in want {
            let mut found = false;
            for g in got {
                if g == w {
                    found = true;
                    break;
                }
            }
            assert!(found, "Did not find {w:?}\ngot: {got:?}");
        }
        assert_eq!(
            want.len(),
            got.len(),
            "got and want different lengths for {more}:\nwant: {want:?}\ngot: {got:?}"
        );
    }

    #[test]
    fn disconnected_outgoing_timeout() -> Result<()> {
        let mut data = Data::new(Addr::new("M0THC-1")?);
        let con = Disconnected::new();

        // First attempt.
        dbg!("First attempt");
        let (con, events) = handle(
            &con,
            &mut data,
            &Event::Connect(Addr::new("M0THC-2")?, false),
        );
        let con = con.unwrap();
        assert_eq!(con.name(), "AwaitingConnection");
        assert_eq!(data.peer, Some(Addr::new("M0THC-2")?));
        assert_all(
            &[ReturnEvent::Packet(Packet {
                src: Addr::new("M0THC-1")?,
                dst: Addr::new("M0THC-2")?,
                command_response: true,
                command_response_la: false,
                digipeater: vec![],
                rr_dist1: false,
                rr_extseq: false,
                packet_type: PacketType::Sabm(Sabm { poll: true }),
            })],
            &events,
            "connect",
        );

        for retry in 1.. {
            dbg!("Retry", retry);
            let (c2, events) = handle(&*con, &mut data, &Event::T1);
            if retry == 3 {
                assert_eq!(c2.unwrap().name(), "Disconnected");
                break;
            } else {
                assert!(matches![c2, None]);
                assert_eq!(data.peer, Some(Addr::new("M0THC-2")?));
                assert_all(
                    &[ReturnEvent::Packet(Packet {
                        src: Addr::new("M0THC-1")?,
                        dst: Addr::new("M0THC-2")?,
                        command_response: true,
                        command_response_la: false,
                        digipeater: vec![],
                        rr_dist1: false,
                        rr_extseq: false,
                        packet_type: PacketType::Sabm(Sabm { poll: true }),
                    })],
                    &events,
                    "connect",
                );
            }
        }
        Ok(())
    }

    #[test]
    fn disconnected_incoming() -> Result<()> {
        let mut data = Data::new(Addr::new("M0THC-1")?);
        data.able_to_establish = true; // TODO: implement some sort of listen()
        let con = Disconnected::new();

        let (con, events) = handle(
            &con,
            &mut data,
            &Event::Sabm(Sabm { poll: true }, Addr::new("M0THC-2")?),
        );
        let con = con.unwrap();
        assert_eq!(con.name(), "Connected");
        assert_eq!(data.peer, Some(Addr::new("M0THC-2")?));
        assert_all(
            &[ReturnEvent::Packet(Packet {
                src: Addr::new("M0THC-1")?,
                dst: Addr::new("M0THC-2")?,
                command_response: true,
                command_response_la: false,
                digipeater: vec![],
                rr_dist1: false,
                rr_extseq: false,
                packet_type: PacketType::Ua(Ua { poll: true }),
            })],
            &events,
            "connect",
        );
        Ok(())
    }

    #[test]
    fn connected() -> Result<()> {
        let mut data = Data::new(Addr::new("M0THC-1")?);
        data.peer = Some(Addr::new("M0THC-2")?);
        let con = Connected::new(ConnectedState::Connected);

        // Receive data packet.
        let (c2, events) = handle(
            &con,
            &mut data,
            &Event::Iframe(
                Iframe {
                    nr: 0,
                    ns: 0,
                    poll: true, // TODO: poll or no?
                    pid: 0xF0,
                    payload: vec![1, 2, 3],
                },
                true,
            ),
        );
        assert!(matches![c2, None]);
        assert_all(
            &[
                ReturnEvent::Data(Res::Some(vec![1, 2, 3])),
                ReturnEvent::Packet(Packet {
                    src: Addr::new("M0THC-1")?,
                    dst: Addr::new("M0THC-2")?,
                    command_response: false,
                    command_response_la: true,
                    digipeater: vec![],
                    rr_dist1: false,
                    rr_extseq: false,
                    packet_type: PacketType::Rr(Rr { poll: true, nr: 1 }),
                }),
            ],
            &events,
            "iframe",
        );

        eprintln!("Receive repeated packet");
        let (c2, events) = handle(
            &con,
            &mut data,
            &Event::Iframe(
                Iframe {
                    nr: 0,
                    ns: 0,
                    poll: true, // TODO: poll or no?
                    pid: 0xF0,
                    payload: vec![1, 2, 3],
                },
                true,
            ),
        );
        assert!(matches![c2, None]);
        assert_all(&[], &events, "iframe");

        eprintln!("Receive next packet");
        let (c2, events) = handle(
            &con,
            &mut data,
            &Event::Iframe(
                Iframe {
                    nr: 0,
                    ns: 1,
                    poll: true, // TODO: poll or no?
                    pid: 0xF0,
                    payload: vec![11, 22, 33],
                },
                true,
            ),
        );
        assert!(matches![c2, None]);
        assert_all(
            &[
                ReturnEvent::Data(Res::Some(vec![11, 22, 33])),
                ReturnEvent::Packet(Packet {
                    src: Addr::new("M0THC-1")?,
                    dst: Addr::new("M0THC-2")?,
                    command_response: false,
                    command_response_la: true,
                    digipeater: vec![],
                    rr_dist1: false,
                    rr_extseq: false,
                    packet_type: PacketType::Rr(Rr { poll: true, nr: 2 }),
                }),
            ],
            &events,
            "iframe",
        );
        Ok(())
    }

    #[test]
    fn disconnect() -> Result<()> {
        let mut data = Data::new(Addr::new("M0THC-1")?);
        data.peer = Some(Addr::new("M0THC-2")?);
        let con = Connected::new(ConnectedState::Connected);
        let (c2, events) = handle(&con, &mut data, &Event::Disc(Disc { poll: true }));
        assert_eq!(c2.unwrap().name(), "Disconnected");
        assert_all(
            &[
                ReturnEvent::Data(Res::EOF),
                ReturnEvent::Packet(Packet {
                    src: Addr::new("M0THC-1")?,
                    dst: Addr::new("M0THC-2")?,
                    command_response: true,
                    command_response_la: false,
                    digipeater: vec![],
                    rr_dist1: false,
                    rr_extseq: false,
                    packet_type: PacketType::Ua(Ua { poll: true }),
                }),
            ],
            &events,
            "disconnect",
        );
        Ok(())
    }
}
