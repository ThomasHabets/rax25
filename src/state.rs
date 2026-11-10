//! State machine code for AX.25
//!
//! The state machine is documented in <https://www.tapr.org/pdf/AX25.2.2.pdf>,
//! but it has a few bugs. They're pointed out in the code as they are
//! encountered.
//!
//! There's also the 2017 version, but it quite possibly added more bugs than it
//! fixed:
//! <https://wiki.oarc.uk/_media/packet:ax25.2.2.10.pdf>
//!
//! All page numbers, unless otherwise specified, are for the 1998 PDF.
//!
//! There's also isomer's useful notes at the top of
//! <https://github.com/isomer/ax25embed/blob/main/ax25/ax25_dl.c>
use std::collections::{HashSet, VecDeque};

use log::{debug, error, warn};

use crate::Addr;
use crate::Result;
use crate::{
    Callsign, CommandResponse, Disc, Dm, Frmr, Iframe, Packet, PacketType, PollFinal, Rej, Rnr, Rr,
    Sabm, Sabme, Srej, Test, Ua, Ui, Xid,
};

#[path = "negotiation.rs"]
pub mod negotiation;
pub use negotiation::{NegotiatedParameters, XidConfig};

/// Incoming events to the state machine.
///
/// An incoming event is an incoming packet, or a command from the application,
/// like "connect", or "send this data".
#[derive(Debug, PartialEq)]
pub enum Event {
    Connect {
        addr: Callsign,
        ext: bool,
    },
    ConnectWithXid {
        addr: Callsign,
        ext: Option<bool>,
    },
    Disconnect,
    Data(Vec<u8>),
    T1,
    T3,
    ManagementTimeout,

    // U frames.
    // Commands.
    Sabm(Sabm, /* peer */ Callsign),
    Sabme(Sabme, /* peer */ Callsign),
    Disc(Disc),
    // Responses.
    Dm(Dm),
    Ua(Ua),
    Frmr(Frmr),
    // Commands or responses.
    Ui(Ui, /* command */ CommandResponse),
    Test(Test, /* command */ CommandResponse),
    Xid(
        Xid,
        /* command */ CommandResponse,
        /* peer */ Callsign,
    ),

    // S frames.
    Rr(Rr, /* command */ CommandResponse),
    Rnr(Rnr),
    Rej(Rej, /* command */ CommandResponse),
    Srej(Srej),

    // I frames.
    Iframe(Iframe, /* command */ CommandResponse),
}

/// Return events, that the state machine wants to tell the world.
///
/// IOW this excludes state changes, since only the state code needs to know
/// about that.
// TODO: also implement the other notifications like `DlDisconnectConfirm`.
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
    #[must_use]
    pub fn serialize(&self) -> Option<Vec<u8>> {
        self.serialize_with_linux_extended_hint(true)
    }

    /// Serialize a packet event with optional Linux extended-mode signalling.
    #[must_use]
    pub fn serialize_with_linux_extended_hint(&self, enabled: bool) -> Option<Vec<u8>> {
        match self {
            ReturnEvent::Packet(p) => Some(p.serialize_with_linux_extended_hint(enabled)),
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

/// Data-link errors.
///
/// Error codes of all kinds.
///
/// * 1984: n/a
/// * 1998: C4.3, page 81
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
                DlError::C =>
                    "C: Unexpected UA in states 3 (Connected), 4 (TimerRecovery), 5 (Awaiting v2.2 Connection)",
                DlError::D => "D: UA received without F=1 when SABM or DISC was sent P=1",
                DlError::E =>
                    "E: DM received in states 3 (Connected), 4 (TimerRecovery), 5 (Awaiting v2.2 Connection)",

                DlError::F =>
                    "F: Data link reset; i.e., SABM received in state 3 (Connected), 4 (TimerRecovery), 5 (Awaiting v2.2 Connection)",
                // 1998 Spec bug: Undocumented.
                DlError::G => "G: Connection timed out",
                // 1998 Spec bug: Undocumented.
                DlError::H => "H: Undocumented. May mean connection timed out while disconnecting",
                DlError::I => "I: N2 timeouts; unacknowledged data",
                DlError::J => "J: N(r) sequence error",
                // 1998 Spec bug: Undocumented.
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

/// Actions are like [`ReturnEvent`], except packets are separated.
///
/// Basically anything the state machine wants to do, aside from
/// modifying the `Data` struct, is to produce "Actions".
///
/// TODO: Terminology here is not very great.
pub enum Action {
    State(Box<dyn State>),
    DlError(DlError),
    SendUa {
        pf: PollFinal,
    },
    SendRr {
        pf: PollFinal,
        nr: u8,
        command: CommandResponse,
    },
    SendRej {
        pf: PollFinal,
        nr: u8,
    },
    SendRnr {
        pf: PollFinal,
        nr: u8,
        command: CommandResponse,
    },
    SendDisc {
        pf: PollFinal,
    },
    SendIframe(Iframe),
    SendDm {
        pf: PollFinal,
    },
    SendSabm {
        pf: PollFinal,
    },
    SendXid {
        peer: Callsign,
        command: CommandResponse,
        xid: Xid,
    },
    Deliver(Vec<u8>),
    EOF,
}

/// I made a note that spec says 3s, but can no longer find that.
///
/// Linux uses 10s, but I feel that's too long.
pub const DEFAULT_SRT: std::time::Duration = std::time::Duration::from_secs(3);

/// Default maximum outgoing frame size.
///
/// This is the transmitting part of what the spec calls `N1`.
/// Spec bug: 4.3.3.7 page 26 says `N1` is retry count, but that's `N2`.
///
/// Higher makes for more efficient bulk transfers in a less noisy environment,
/// but makes retransmissions more expensive.
///
/// This is used for outgoing packets only. We're more liberal in what we
/// receive.
///
/// * Linux uses 256 by default.
/// * Spec says 2048, but in 4.3.3.7 it clarifies that this is bits, so 256
///   bytes there too.
/// * I've seen Kenwood TH-D74 crash when "too big", but have not found the
///   precise number.
pub const DEFAULT_MTU_OUT: usize = 256;

/// Default maximum incoming frame size.
pub const DEFAULT_MTU_IN: usize = 65535;

// Output buffer size is kept in RAM, so should not grow unbounded.
//
// At the expected speeds, 100MB is way more than what we should expect to
// send in any connection.
const MAX_OBUF_SIZE: usize = 100_000_000;

/// "T3 should be greater than T1". 6.7.1.3.
/// Linux uses 5min.
///
/// TODO: need to tune this?
pub const DEFAULT_T3V: std::time::Duration = std::time::Duration::from_secs(10);

/// Max retry count.
///
/// Linux uses 10. It's also set to 10 in the 1998 spec, page 109, figure C4.7,
/// for both extended and not. Page 102 in 2017 spec.
///
/// Also 4.3.3.7 says 10 is the default. Not sure why the diagrams need to set
/// it, then.
pub const DEFAULT_N2: u8 = 10;

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
    #[must_use]
    pub fn is_expired(&self) -> Option<bool> {
        if !self.running {
            return None;
        }
        Some(std::time::Instant::now() > self.expiry)
    }

    /// Return the remaining time of the timer, if it's running.
    #[must_use]
    pub fn remaining(&self) -> Option<std::time::Duration> {
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

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Modulus {
    Standard = 8,
    Extended = 128,
}

impl Modulus {
    #[allow(unused)]
    pub fn is_extended(self) -> bool {
        self == Modulus::Extended
    }
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Connection (or socket, if you will) extra data.
///
/// The state object only carries the state itself. Further data is in this
/// object.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)] // Keep state variables aligned with the AX.25 specification.
pub struct Data {
    pub(crate) linux_extended_hint: bool,
    xid_config: Option<XidConfig>,
    negotiated: Option<NegotiatedParameters>,
    management: Timer,
    management_retries: u8,
    xid_extended: bool,
    xid_required_mode: Option<bool>,
    pending_xid: VecDeque<(Callsign, NegotiatedParameters, std::time::Instant)>,
    /// My local address.
    pub(crate) me: Callsign,

    /// Address of the other side of the connection. Not set during
    /// Disconnected, waiting for remote end to connect.
    pub(crate) peer: Option<Callsign>,

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
    pub(crate) t1: Timer,

    /// T3 timer - Connection idle timer. (4.4.5.2, page 30)
    ///
    /// When no data is pending ACK (and therefore T1 running), T3 is running.
    /// If it expires, it'll trigger RR/RNR, to probe.
    pub(crate) t3: Timer,

    /// T3 timer duration.
    ///
    /// The name here is made up.
    t3v: std::time::Duration,

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

    /// Max incoming packet payload size.
    ///
    /// Max outgoing packet payload size is in `mtu_out`.
    ///
    /// Spec says 256 bytes, but why not allow bigger if it does come in? See
    /// `DEFAULT_MTU_IN`.
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
    pub(crate) modulus: Modulus,

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
    pub(crate) able_to_establish: bool,

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
    ///
    /// * I believe this is what Linux calls "window", where it uses 2 and 32,
    ///   for mod-8 and mod-128.
    /// * 1998 spec says 4 and 32.
    /// * 2017 spec says 8 and 32. 8 can't be right? Bug: this change is not
    ///   hilighted.
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
    mtu_out: usize,
    mtu_out_default: usize,

    /// When an IFRAME is sent out, it's stared in this queue, until it's been
    /// acked. When a resend is required, it's sent from here.
    iframe_resend_queue: VecDeque<Iframe>,

    experiments: HashSet<Experiment>,
}

/// A set of experiments to enable on the implementation outside of the official
/// spec.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, clap::ValueEnum)]
pub enum Experiment {
    /// Normally, when an iframe arrives with a new ACK value, that will
    /// register the ACK just fine and deliver the data. But it doesn't cause
    /// the retry counter to reset.
    ///
    /// So even though both peers may be getting data through and make progress,
    /// they may both "give up" and end the connection with a DM.
    ///
    /// That kind of makes sense, in that an RR response means "I heard you".
    /// But so does an iframe with a new sequence number.
    ///
    /// <https://github.com/packethacking/ax25spec/issues/9>
    ResetRetryOnAckUpdate,
    /// Normally, we only retransmit if we get an RR response. But if we are
    /// waiting for an RR response, and we get an RR command, why not issue the
    /// retransmit right now.
    ///
    /// <https://github.com/packethacking/ax25spec/issues/8>
    ResendOnRrCommand,
}

impl Data {
    /// Number of buffered or unacknowledged data frames.
    #[must_use]
    pub fn pending_frames(&self) -> usize {
        self.iframe_resend_queue.len() + self.obuf.len().div_ceil(self.mtu_out)
    }
    /// Create new Data with the specified address being the local one.
    #[must_use]
    pub fn new(me: Callsign) -> Self {
        Self {
            me,
            linux_extended_hint: true,
            xid_config: None,
            negotiated: None,
            management: Timer::default(),
            management_retries: 0,
            xid_extended: false,
            xid_required_mode: None,
            pending_xid: VecDeque::new(),
            peer: None,
            n1: DEFAULT_MTU_IN,
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
            modulus: Modulus::Standard,
            peer_receiver_busy: false,
            reject_exception: false,
            sreject_exception: 0,
            srej_enabled: false,
            acknowledge_pending: false,
            own_receiver_busy: false,
            iframe_queue: Vec::new(),
            mtu_out: DEFAULT_MTU_OUT,
            mtu_out_default: DEFAULT_MTU_OUT,
            obuf: VecDeque::new(),
            iframe_resend_queue: VecDeque::new(),
            able_to_establish: false,
            experiments: HashSet::new(),
        }
    }

    /// Enable the outgoing Linux source-address extended-mode hint (default true).
    /// This does not change the sequencing mode or receive parsing.
    pub fn set_linux_extended_hint(&mut self, enabled: bool) {
        self.linux_extended_hint = enabled;
    }

    /// Set default T1 timer / smoothed roundtrip.
    pub fn srt_default(&mut self, v: std::time::Duration) {
        self.srt_default = v;
    }

    /// Set T3 / idle timer.
    pub fn t3v(&mut self, v: std::time::Duration) {
        self.t3v = v;
    }

    /// Enable an experiment.
    pub fn enable_experiment(&mut self, ex: Experiment) {
        self.experiments.insert(ex);
    }

    /// Set MTU.
    pub fn mtu(&mut self, v: usize) {
        self.mtu_out = v;
        self.mtu_out_default = v;
    }

    /// Enable XID for outgoing connections and listening responders.
    pub fn set_xid_config(&mut self, config: XidConfig) {
        self.xid_config = Some(config);
    }

    /// Validate local policy before sending frames.
    pub fn validate_xid_config(&self) -> Result<()> {
        self.xid_config.as_ref().map_or(Ok(()), XidConfig::validate)
    }

    /// Clear XID policy and pending proposals, stopping management retries.
    /// This does not transition the link state; disconnect to abandon an
    /// in-progress connection attempt.
    pub fn clear_xid_config(&mut self) {
        self.management.stop();
        self.xid_config = None;
        self.pending_xid.clear();
    }

    #[must_use]
    pub fn negotiated_parameters(&self) -> Option<&NegotiatedParameters> {
        self.negotiated.as_ref()
    }

    /// Make a fresh accepted connection retaining listener negotiation state.
    #[must_use]
    pub fn accepted_data(&mut self, peer: &Callsign) -> Self {
        let mut data = Self::new(self.me.clone());
        data.linux_extended_hint = self.linux_extended_hint;
        data.xid_config.clone_from(&self.xid_config);
        self.expire_pending_xid();
        if let Some(index) = self
            .pending_xid
            .iter()
            .position(|(addr, _, _)| addr == peer)
            && let Some(proposal) = self.pending_xid.remove(index)
        {
            data.pending_xid.push_back(proposal);
        }
        data.srt_default = self.srt_default;
        data.t3v = self.t3v;
        data.mtu_out = self.mtu_out_default;
        data.mtu_out_default = self.mtu_out_default;
        data.experiments.clone_from(&self.experiments);
        data.able_to_establish = true;
        data
    }

    #[must_use]
    pub fn management_expired(&self) -> bool {
        self.management.is_expired().unwrap_or(false)
    }

    #[must_use]
    pub fn management_remaining(&self) -> Option<std::time::Duration> {
        self.management.remaining()
    }

    fn apply_negotiated(&mut self, parameters: NegotiatedParameters) {
        self.n1 = parameters.receive_length;
        self.mtu_out = parameters.transmit_length;
        self.k = parameters.transmit_window;
        self.n2 = parameters.retries;
        self.srt = parameters.acknowledgement_timer;
        self.t1v = parameters.acknowledgement_timer;
        self.negotiated = Some(parameters);
    }

    fn xid_command(&self) -> Action {
        Action::SendXid {
            peer: self.peer.clone().expect("XID requires a peer"),
            command: CommandResponse::Command,
            xid: Xid {
                poll: PollFinal::Set,
                parameters: Some(
                    self.xid_config
                        .as_ref()
                        .expect("XID requires config")
                        .offer(self.xid_extended),
                ),
            },
        }
    }

    fn start_xid(&mut self, peer: &Callsign, extended: Option<bool>) -> Vec<Action> {
        let config = self.xid_config.get_or_insert_with(XidConfig::default);
        if config.validate().is_err() {
            return vec![Action::DlError(DlError::K)];
        }
        self.management.start(config.management_timeout);
        self.management_retries = 0;
        self.xid_extended = extended.unwrap_or(true);
        self.xid_required_mode = extended;
        self.peer = Some(peer.clone());
        self.negotiated = None;
        self.layer3_initiated = true;
        self.t1.stop();
        self.t3.stop();
        vec![Action::State(Box::new(AwaitingXid)), self.xid_command()]
    }

    fn finish_xid(&mut self, parameters: Option<NegotiatedParameters>) -> Vec<Action> {
        self.management.stop();
        self.negotiated = None;
        self.mtu_out = self.mtu_out_default;
        if parameters.as_ref().is_some_and(|p| p.extended) {
            self.set_version_2_2();
        } else {
            self.set_version_2();
        }
        self.srt = self.srt_default;
        self.t1v = 2 * self.srt;
        if let Some(parameters) = parameters {
            self.apply_negotiated(parameters);
        } else {
            self.n1 = 256;
            self.mtu_out = self.mtu_out.min(256);
            self.srt = DEFAULT_SRT;
            self.t1v = DEFAULT_SRT;
        }
        vec![
            Action::State(Box::new(AwaitingConnection::new())),
            self.establish_data_link(),
        ]
    }

    fn expire_pending_xid(&mut self) {
        let now = std::time::Instant::now();
        self.pending_xid.retain(|(_, _, expiry)| *expiry > now);
    }

    fn receive_xid(
        &mut self,
        packet: &Xid,
        command: CommandResponse,
        peer: &Callsign,
    ) -> Vec<Action> {
        self.expire_pending_xid();
        let config = self.xid_config.clone().unwrap_or_default();
        if config.validate().is_err() {
            return vec![];
        }
        if command.is_command() {
            if !packet.poll.is_set() {
                return vec![];
            }
            let mut response = config.offer(true);
            if let Some(offered) = &packet.parameters {
                let Some(parameters) = config.negotiate(offered, true, self.mtu_out) else {
                    return vec![];
                };
                response = config.offer(parameters.extended);
                response.optional_functions = Some(
                    response.optional_functions.unwrap()
                        & !if parameters.extended {
                            negotiation::MOD8
                        } else {
                            negotiation::MOD128
                        },
                );
                response.acknowledgement_timer_ms = Some(
                    u32::try_from(parameters.acknowledgement_timer.as_millis())
                        .expect("validated timer"),
                );
                response.retries = Some(parameters.retries);
                self.pending_xid.retain(|(addr, _, _)| addr != peer);
                if self.pending_xid.len() == 16 {
                    self.pending_xid.pop_front();
                }
                let lifetime = config
                    .management_timeout
                    .saturating_mul(u32::from(config.management_retries) + 2);
                self.pending_xid.push_back((
                    peer.clone(),
                    parameters,
                    std::time::Instant::now() + lifetime,
                ));
            }
            return vec![Action::SendXid {
                peer: peer.clone(),
                command: CommandResponse::Response,
                xid: Xid {
                    poll: packet.poll,
                    parameters: Some(response),
                },
            }];
        }
        if !self.management.running
            || !packet.poll.is_set()
            || self.peer.as_ref().is_none_or(|addr| addr != peer)
        {
            return vec![];
        }
        let parameters = packet
            .parameters
            .as_ref()
            .and_then(|p| config.negotiate(p, self.xid_extended, self.mtu_out))
            .filter(|p| {
                self.xid_required_mode
                    .is_none_or(|required| p.extended == required)
            });
        self.finish_xid(parameters)
    }

    /// Return true if using 128 modulus.
    #[must_use]
    pub fn ext(&self) -> bool {
        self.modulus == Modulus::Extended
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
        if self.management_expired() {
            ret.push(Event::ManagementTimeout);
        }
        ret
    }

    /// Return time until next timer expires, or None if no timer is currently
    /// running.
    #[must_use]
    #[allow(clippy::match_same_arms)]
    pub fn next_timer_remaining(&self) -> Option<std::time::Duration> {
        [
            self.t1.remaining(),
            self.t3.remaining(),
            self.management.remaining(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Do something with a received UI frame.
    ///
    /// Unnumbered information is pretty uninteresting here, since this crate
    /// handles connected mode.
    ///
    /// But we should probably add some UI support. It wouldn't be much code.
    ///
    /// * 1998: C4.7, page 108.
    #[must_use]
    fn ui_check(&self, command: CommandResponse, len: usize) -> Vec<Action> {
        if command.is_response() {
            // 1998-2017 Spec bug: error Q says this is also for UI frames with
            // Poll set.
            //
            // But 4.3.3.6 says command+poll is just fine, and should just trigger
            // DM.
            //
            // So probably the code as-is, is correct, and the Q error message
            // should be changed.
            return vec![Action::DlError(DlError::Q)];
        }
        // TODO: 4.3.3.6 says that if poll is set:
        // * If we are disconnected, send DM.
        // * If we are connected, send RR or RNR.
        //
        // This is not in the diagrams.
        if len > self.n1 {
            return vec![Action::DlError(DlError::K)];
        }
        debug!("rax25: DL-UNIT_DATA indication");
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
    fn check_need_for_response(&mut self, command: CommandResponse, pf: PollFinal) -> Vec<Action> {
        match (command, pf) {
            // A command with poll set demands a response with fin set.
            (CommandResponse::Command, PollFinal::Set) => {
                vec![self.enquiry_response(PollFinal::Set)]
            }

            // I believe that this means the state is currently Connected,
            // and therefore we're not waiting for a response.
            (CommandResponse::Response, PollFinal::Set) => vec![Action::DlError(DlError::A)],

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
    /// In the parts currently implemented, `pf` is always `PollFinal::Set`.
    ///
    /// Page 106.
    #[must_use]
    fn enquiry_response(&mut self, pf: PollFinal) -> Action {
        self.acknowledge_pending = false;
        // TODO: 2017 spec has a bit more complex diagram here. Some of it is
        // correct, but other stuff I'm not so sure of.
        //
        // Most of it is SREJ related, but it also says to send RR instead of
        // RNR if not `F==1 && (RR || RNR || I)`.
        if self.own_receiver_busy {
            // 1998 spec doesn't say, but 2017 spec says "Response".
            Action::SendRnr {
                pf,
                nr: self.vr,
                command: CommandResponse::Response,
            }
        } else {
            // 1998 spec says commmand, which is wrong.
            Action::SendRr {
                pf,
                nr: self.vr,
                command: CommandResponse::Response,
            }
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
        // Direwolf has an interesting comment here that perhaps what we
        // actually want is a check with state Connected, not rc=0.
        //
        // Or maybe we set rc=0 everywhere we enter Connected?
        if self.rc == 0 {
            // TODO: the real formula is stranger.
            self.srt = self
                .negotiated
                .as_ref()
                .map_or(self.srt_default, |p| p.acknowledgement_timer);
        } else if self.t1_expired() {
            // 1998 spec says:
            // self.srt = self.srt * (2 ** (rc + 1));

            // 2017 spec formula.
            // It's unclear what unit `rc` is supposed to be. It's retry
            // counter. I'll assume seconds, to millisecond resolution.
            // SRT = RC / 4 + SRT*2
            let t = std::time::Duration::from_millis(u64::from(self.rc) * 250);
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
            Action::SendRnr {
                pf: PollFinal::Set,
                nr: self.vr,
                command: CommandResponse::Command,
            }
        } else {
            Action::SendRr {
                pf: PollFinal::Set,
                nr: self.vr,
                command: CommandResponse::Command,
            }
        }
    }

    /// When RR is received, incorporate any new info, and potentially
    /// wait for more RRs.
    ///
    /// Page 107.
    #[must_use]
    fn check_iframe_acked(&mut self, nr: u8) -> Vec<Action> {
        // Typo in 1998 spec. Says "peer busy".
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
    /// In the 1998/2017 spec this is just `va <- nr`, which hides the
    /// complexity.
    #[must_use]
    fn update_ack(&mut self, nr: u8) -> Vec<Action> {
        // dbg!(self.va, nr);
        // debug!("Updating ack to {} {}", self.va, nr);
        while self.va != nr {
            assert!(!self.iframe_resend_queue.is_empty());
            self.iframe_resend_queue.pop_front();
            self.va = (self.va + 1) % self.modulus.as_u8();
            if self
                .experiments
                .contains(&Experiment::ResetRetryOnAckUpdate)
            {
                self.rc = 0;
            }
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
        Action::SendSabm { pf: PollFinal::Set }
    }

    /// Set values for extended sequence number connection.
    ///
    /// Page 109.
    pub(crate) fn set_version_2_2(&mut self) {
        // TODO: set half duplex SREJ
        self.modulus = Modulus::Extended;
        // TODO: n1r = 2048

        // 1998 Spec bug: Spec says `kr`. Surely it means `k`?
        self.k = 32;

        // TODO: self.t2.set(3000);
        self.n2 = 10;
    }

    /// Set values for mod-8 connections.
    ///
    /// Page 109.
    pub(crate) fn set_version_2(&mut self) {
        self.modulus = Modulus::Standard;
        // TODO: n1r = 2048

        // 1998 Spec bug: Spec says `kr`. Surely it means `k`?
        // 2025 spec says 8.
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
            if self.vs == (self.va + self.k) % self.modulus.as_u8() {
                debug!(
                    "rax25: tx window full with more data ({} bytes) to send!",
                    self.obuf.len()
                );
                break;
            }
            let payload = self
                .obuf
                .drain(..std::cmp::min(self.mtu_out, self.obuf.len()))
                .collect::<Vec<_>>();
            let ns = self.vs;
            self.vs = (self.vs + 1) % self.modulus.as_u8();
            self.acknowledge_pending = false;
            // TODO: Direwolf makes a good point about always restarting T1,
            // here. I'm not sure yet.
            if !self.t1.running {
                self.t3.stop();
                self.t1.start(self.srt);
            }
            let i = Iframe {
                ns,
                nr: self.vr,
                poll: PollFinal::Clear,
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
    fn connect(&self, _data: &mut Data, _addr: &Callsign, _ext: bool) -> Vec<Action> {
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
    fn t1(&self, data: &mut Data) -> Vec<Action> {
        data.t1.stop();
        eprintln!("TODO: unexpected T1 expire");
        vec![]
    }

    /// Timer T3 (connection keepalive) expires.
    #[must_use]
    fn t3(&self, data: &mut Data) -> Vec<Action> {
        data.t3.stop();
        eprintln!("TODO: unexpected T3 expire");
        vec![]
    }

    /// RR received from peer.
    #[must_use]
    fn rr(&self, _data: &mut Data, _packet: &Rr, _command: CommandResponse) -> Vec<Action> {
        eprintln!("TODO: unexpected RR");
        vec![]
    }

    /// REJ received from peer.
    #[must_use]
    fn rej(&self, _data: &mut Data, _packet: &Rej, _command: CommandResponse) -> Vec<Action> {
        eprintln!("TODO: unexpected REJ");
        vec![]
    }

    /// XID received from peer.
    #[must_use]
    fn xid(&self, _data: &mut Data, _packet: &Xid, _cr: CommandResponse) -> Vec<Action> {
        eprintln!("TODO: unexpected XID");
        vec![]
    }

    /// TEST received from peer.
    #[must_use]
    fn test(&self, _data: &mut Data, _packet: &Test, _cr: CommandResponse) -> Vec<Action> {
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
    fn sabm(&self, _data: &mut Data, _src: &Callsign, _packet: &Sabm) -> Vec<Action> {
        eprintln!("TODO: unexpected SABM");
        vec![]
    }

    /// SABME received from peer.
    #[must_use]
    fn sabme(&self, _data: &mut Data, _src: &Callsign, _packet: &Sabme) -> Vec<Action> {
        eprintln!("TODO: unexpected SABME");
        vec![]
    }

    /// IFRAME received from peer.
    #[must_use]
    fn iframe(&self, _data: &mut Data, _packet: &Iframe, _cr: CommandResponse) -> Vec<Action> {
        eprintln!("TODO; unexpected iframe");
        vec![]
    }

    /// UI received from peer.
    #[must_use]
    fn ui(&self, _data: &mut Data, _cr: CommandResponse, _packet: &Ui) -> Vec<Action> {
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
    #[allow(clippy::unused_self)]
    fn sabm_and_sabme(&self, data: &mut Data, src: Callsign, pf: PollFinal) -> Vec<Action> {
        debug!("rax25: DL-Connect indication from {:?}", src.call());
        if !data.able_to_establish {
            return vec![Action::SendDm { pf }];
        }
        data.clear_exception_conditions();
        data.vs = 0;
        data.va = 0;
        data.vr = 0;
        data.srt = data.srt_default;
        data.t1v = data.srt + data.srt;
        data.negotiated = None;
        data.n1 = DEFAULT_MTU_IN;
        data.mtu_out = data.mtu_out_default;
        data.expire_pending_xid();
        if let Some(index) = data
            .pending_xid
            .iter()
            .position(|(peer, p, _)| peer == &src && p.extended == data.ext())
        {
            let (_, parameters, _) = data.pending_xid.remove(index).unwrap();
            data.apply_negotiated(parameters);
            // SABM cannot distinguish a negotiated peer from one whose XID
            // responses were all lost. Tolerate legacy-sized receive frames.
            data.n1 = data.n1.max(DEFAULT_MTU_OUT);
        }
        data.t3.start(data.t3v);
        data.rc = 0;
        data.peer = Some(src);
        vec![
            Action::SendUa { pf },
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
    fn connect(&self, data: &mut Data, addr: &Callsign, ext: bool) -> Vec<Action> {
        if data.xid_config.is_some() {
            return data.start_xid(addr, Some(ext));
        }
        data.negotiated = None;
        data.modulus = if ext {
            Modulus::Extended
        } else {
            Modulus::Standard
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

    // Figure C4.1
    //
    // ## 1998
    //
    // Page 84.
    //
    // ## 2006
    //
    // Page 88. Typo in top left, should be "DL-DISCONNECT Request" triggers
    // confirm and no state change, not "DL-CONNECT Request".
    //
    // ## 2017
    //
    // Page 88.
    fn disconnect(&self, _data: &mut Data) -> Vec<Action> {
        debug!("rax25: Disconnect while already disconnected");
        // TODO: issue DlDisconnectConfirm.
        vec![]
    }

    // Page 84.
    fn ui(&self, data: &mut Data, cr: CommandResponse, packet: &Ui) -> Vec<Action> {
        let mut ret = data.ui_check(cr, packet.payload.len());
        if packet.push.is_set() {
            ret.push(Action::SendDm { pf: PollFinal::Set });
        }
        ret
    }

    // Page 85.
    fn sabm(&self, data: &mut Data, src: &Callsign, sabm: &Sabm) -> Vec<Action> {
        data.set_version_2();
        self.sabm_and_sabme(data, src.clone(), sabm.poll)
    }

    // Page 85.
    fn sabme(&self, data: &mut Data, src: &Callsign, packet: &Sabme) -> Vec<Action> {
        data.set_version_2_2();
        self.sabm_and_sabme(data, src.clone(), packet.poll)
    }

    // Page 84.
    fn dm(&self, _data: &mut Data, _packet: &Dm) -> Vec<Action> {
        vec![]
    }

    // Page 84.
    fn ua(&self, _data: &mut Data, _packet: &Ua) -> Vec<Action> {
        // 1998 & 2017 bug: C and D make no sense here.
        vec![Action::DlError(DlError::C), Action::DlError(DlError::D)]
    }

    // Page 84.
    fn disc(&self, _data: &mut Data, packet: &Disc) -> Vec<Action> {
        vec![Action::SendDm { pf: packet.poll }]
    }
}

// AwaitingConnection means a SABM(E) has been sent, and we are waiting for the
// UA.
struct AwaitingConnection {}

/// Negotiation precedes SABM(E), following 4.3.3.7 and 6.3.2 rather than
/// the conflicting post-connect exchange in appendix C5.
struct AwaitingXid;

impl State for AwaitingXid {
    fn name(&self) -> String {
        "AwaitingXid".to_string()
    }

    fn disconnect(&self, data: &mut Data) -> Vec<Action> {
        data.management.stop();
        data.negotiated = None;
        vec![Action::State(Box::new(Disconnected::new())), Action::EOF]
    }

    fn dm(&self, data: &mut Data, packet: &Dm) -> Vec<Action> {
        if packet.poll.is_set() {
            data.finish_xid(None)
        } else {
            vec![]
        }
    }

    fn frmr(&self, data: &mut Data) -> Vec<Action> {
        data.finish_xid(None)
    }
}

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
        data.t1.stop();
        if data.rc == data.n2 {
            debug!("t1 expired while connecting for the last time. Giving up");
            data.clear_iframe_queue();
            vec![
                // 1998 spec bug: Typo: G, not g.
                Action::DlError(DlError::G),
                Action::State(Box::new(Disconnected::new())),
            ]
        } else {
            debug!("t1 expired while connecting, retrying");
            data.rc += 1;
            data.select_t1_value();
            data.t1.start(data.srt);
            vec![Action::SendSabm { pf: PollFinal::Set }]
        }
    }

    // Page 88.
    fn ua(&self, data: &mut Data, packet: &Ua) -> Vec<Action> {
        let f = packet.poll;
        if !f.is_set() {
            return vec![Action::DlError(DlError::D)];
        }
        if data.layer3_initiated {
            debug!("rax25: DL-CONNECT CONFIRM");
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
            debug!("rax25: DL-CONNECT CONFIRM, vs!=va");
            warn!("rax25: Strange state entered: UA received while vs != va");
        }
        data.t1.stop();

        // 1998 spec says "stop T3".
        // 2017 spec says "start T3" (page 89), which makes much more sense.
        data.t3.start(data.t3v);

        data.vs = 0;
        data.va = 0;
        data.vr = 0;
        data.rc = 0; // Missing from 1998 & 2017 spec, but done by direwolf.
        data.select_t1_value();
        vec![Action::State(Box::new(Connected::new(
            ConnectedState::Connected,
        )))]
    }

    // Page 86.
    fn sabm(&self, _data: &mut Data, _src: &Callsign, packet: &Sabm) -> Vec<Action> {
        vec![Action::SendUa { pf: packet.poll }]
    }

    // Page 88.
    fn sabme(&self, _data: &mut Data, _src: &Callsign, packet: &Sabme) -> Vec<Action> {
        // TODO: This is supposed to transition to "awaiting connect 2.2".
        vec![Action::SendDm { pf: packet.poll }]
    }

    // Page 86.
    fn disconnect(&self, data: &mut Data) -> Vec<Action> {
        // 1998&2017 bug: It says "requeue". What does that even mean? Run this
        // same function again?
        data.t1.stop(); // Because we're heading into Disconnected.
        vec![
            Action::SendDisc { pf: PollFinal::Set },
            Action::State(Box::new(Disconnected::new())),
        ]
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
        if !p.poll.is_set() {
            return vec![];
        }
        debug!("rax25: DL-DISCONNECT Confirm");
        data.t1.stop();
        vec![Action::State(Box::new(Disconnected::new()))]
    }

    // ## 2006
    //
    // C4.3 page 94.
    //
    // ## 1998
    //
    // Page 90.
    fn ua(&self, data: &mut Data, p: &Ua) -> Vec<Action> {
        if !p.poll.is_set() {
            return vec![Action::DlError(DlError::D)];
        }
        debug!("rax25: DL-DISCONNECT confirm");
        data.t1.stop();
        vec![Action::State(Box::new(Disconnected::new()))]
    }

    // Page 91.
    fn t1(&self, data: &mut Data) -> Vec<Action> {
        data.t1.stop();
        if data.rc == data.n2 {
            debug!("rax25: DL-DISCONNECT confirm");
            // 1998 spec bug: if we're going disconnected, then there's no need
            // for timers. So stop t3.
            data.t3.stop();
            return vec![
                Action::DlError(DlError::H),
                Action::State(Box::new(Disconnected::new())),
            ];
        }
        data.rc += 1;
        data.select_t1_value();
        data.t1.start(data.t1v);
        vec![Action::SendDisc { pf: PollFinal::Set }]
    }

    // Page 89.
    fn disconnect(&self, data: &mut Data) -> Vec<Action> {
        // 1998&2017 bug: What's an "expedited" DM?
        data.t1.stop();
        debug!("rax25: DL-DISCONNECT confirm");
        // 1998&2017 bug: Doesn't specify pf.
        vec![
            Action::SendDm {
                pf: PollFinal::Clear,
            },
            Action::State(Box::new(Disconnected::new())),
        ]
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
    #[allow(clippy::unused_self)]
    fn rr_connected(&self, data: &mut Data, packet: &Rr, cr: CommandResponse) -> Vec<Action> {
        data.peer_receiver_busy = false;
        let mut act = data.check_need_for_response(cr, packet.poll);
        if in_range(data.va, packet.nr, data.vs, data.modulus) {
            act.extend(data.check_iframe_acked(packet.nr));
        } else {
            act.extend(data.nr_error_recovery());
            act.push(Action::State(Box::new(AwaitingConnection::new())));
        }
        act
    }

    // C4.5b.
    //
    // ## 2017
    //
    // Page 95.
    //
    // ## 1998
    //
    // Page 99.
    #[must_use]
    #[allow(clippy::unused_self)]
    fn rr_timer_recovery(&self, data: &mut Data, packet: &Rr, cr: CommandResponse) -> Vec<Action> {
        data.peer_receiver_busy = false;
        let mut act = Vec::new();
        let retransmit_path = if data.experiments.contains(&Experiment::ResendOnRrCommand) {
            // If enough time has passed, why not trigger a retransmit (via
            // update_ack) even if this was not a 'command' being sent?
            //
            // TODO: We should not trigger the resend path if while t1 is
            // running (and thus we're waiting for a response), that probe has
            // not yet been sent. Ideally we should even allow for some RTT
            // before retransmitting.
            //
            // More at https://github.com/packethacking/ax25spec/issues/8.
            data.t1.running
        } else {
            cr.is_response() && packet.poll.is_set()
        };
        if retransmit_path {
            data.t1.stop();
            data.select_t1_value();
            if !in_range(data.va, packet.nr, data.vs, data.modulus) {
                let mut act = data.nr_error_recovery();
                act.push(Action::State(Box::new(AwaitingConnection::new())));
                return act;
            }
            act.extend(data.update_ack(packet.nr));
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

                // Direwolf seems to set ack pending to 0, meaning false?
                data.acknowledge_pending = true;
            }
            if !data.experiments.contains(&Experiment::ResendOnRrCommand) {
                return act;
            }
        }
        // 2017 spec bug on page 95: no 'no' path from this if.
        if cr.is_command() && packet.poll.is_set() {
            act.push(data.enquiry_response(PollFinal::Set));
        }
        if in_range(data.va, packet.nr, data.vs, data.modulus) {
            act.extend(data.update_ack(packet.nr));
            // TODO: Direwolf found that state machine can get stuck in
            // TimerRecovery, and we should check for caught up. Disabled for now.
            /*
            if data.va == data.vs {
                data.t1.stop();
                data.select_t1_value();
                data.t3.start(data.t3v);
                data.rc = 0;
                act.push(Action::State(Box::new(Connected::new(
                    ConnectedState::Connected,
                ))));
            }
            */
        } else {
            act.extend(data.nr_error_recovery());
            act.push(Action::State(Box::new(AwaitingConnection::new())));
        }
        act
    }

    // Page 93 and page 99.
    fn sabm_or_sabme(&self, data: &mut Data, poll: PollFinal) -> Vec<Action> {
        data.clear_exception_conditions();
        if data.vs != data.va {
            data.iframe_queue.clear();
            debug!("rax25: DL-Connect indication");
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
            Action::SendUa { pf: poll },
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

    // ## 1998 spec
    //
    // Page 92 & 98.
    //
    // ## 2006 spec
    //
    // C4.4 on page 95 (Connected) and C4.5 101 (TimerRecovery).
    fn disconnect(&self, data: &mut Data) -> Vec<Action> {
        data.clear_iframe_queue();
        data.rc = 0;
        data.t1.start(data.srt); // TODO: with what timer?
        data.t3.stop();
        vec![
            Action::SendDisc { pf: PollFinal::Set },
            Action::State(Box::new(AwaitingRelease::new())),
        ]
    }

    // Page 92 & 98.
    //
    // This implementation deliberately doesn't preserve the application's
    // frame boundaries.
    //
    // This seems like the right thing to do. But in the future maybe we'll
    // implement what Linux would call SEQPACKET, that AX.25 would call
    // segmentation.
    fn data(&self, data: &mut Data, payload: &[u8]) -> Vec<Action> {
        data.obuf.extend(payload);
        assert!(
            data.obuf.len() <= MAX_OBUF_SIZE,
            "TODO: handle better. Output buffer got too large. {} > {}",
            data.obuf.len(),
            MAX_OBUF_SIZE
        );
        data.flush()
    }

    // Page 93.
    //
    // src is ignored, because it's presumed to already have been checked, in
    // this state.
    fn sabm(&self, data: &mut Data, _src: &Callsign, packet: &Sabm) -> Vec<Action> {
        data.set_version_2();
        self.sabm_or_sabme(data, packet.poll)
    }

    // Page 93.
    //
    // src is ignored, because it's presumed to already have been checked, in
    // this state.
    fn sabme(&self, data: &mut Data, _src: &Callsign, packet: &Sabme) -> Vec<Action> {
        data.set_version_2_2();
        self.sabm_or_sabme(data, packet.poll)
    }

    // Page 93 & 101.
    //
    // Done.
    fn dm(&self, data: &mut Data, _packet: &Dm) -> Vec<Action> {
        debug!("rax25: DL-DISCONNECT");
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
            Action::SendUa { pf: p.poll },
            Action::EOF,
            Action::State(Box::new(Disconnected::new())),
        ]
    }

    // iframe for Connected and TimerRecovery.
    //
    // ## 1998
    //
    // C4.5 (page 96) & C4.6 (page 102).
    //
    // ## 2017
    //
    // C4.4c (page 93)  & C4.5c (page 96).
    //
    //
    // TODO; implement segment reassembly.
    #[allow(clippy::too_many_lines)]
    fn iframe(
        &self,
        data: &mut Data,
        p: &Iframe,
        command_response: CommandResponse,
    ) -> Vec<Action> {
        if command_response.is_response() {
            // 2017 spec page 93 says to DlError::O if the iframe *is* a
            // command. That's not even remotely correct, since O means packet
            // too big.
            // The TimerRecovery version on page 96 has the same nonsense, but
            // there the yes/no is not even labelled.
            return vec![Action::DlError(DlError::S)];
        }
        if p.payload.len() > data.n1 {
            debug!("rax25: Discarding frame for being too big");
            data.layer3_initiated = false;
            // TODO: should we discard it? Seems like it's fine to keep, no?
            return vec![
                data.establish_data_link(),
                Action::DlError(DlError::O),
                Action::State(Box::new(AwaitingConnection::new())),
            ];
        }
        if !in_range(data.va, p.nr, data.vs, data.modulus) {
            debug!("rax25: Discarding frame for being out of range");
            let mut acts = data.nr_error_recovery();
            acts.push(Action::State(Box::new(AwaitingConnection::new())));
            return acts;
        }
        let mut actions = vec![];
        if false {
            // 1998 spec.
            match self.connected_state {
                ConnectedState::Connected => actions.extend(data.check_iframe_acked(p.nr)),
                ConnectedState::TimerRecovery => actions.extend(data.update_ack(p.nr)),
            }
        } else {
            // 2017 spec. It's not a hilighted change.
            actions.extend(data.check_iframe_acked(p.nr));
        }

        // TODO: Direwolf found that state machine can get stuck in
        // TimerRecovery, and we should check for caught up. Disabled for now.
        if false
            && let ConnectedState::TimerRecovery = self.connected_state
            && data.va == data.vs
        {
            data.t1.stop();
            data.select_t1_value();
            data.t3.start(data.t3v);
            data.rc = 0;
            actions.push(Action::State(Box::new(Connected::new(
                ConnectedState::Connected,
            ))));
        }
        if data.own_receiver_busy {
            // discord (implicit)
            debug!("rax25: Discarding iframe because busy and being polled");
            if p.poll.is_set() {
                actions.push(Action::SendRnr {
                    pf: PollFinal::Set,
                    nr: data.vr,
                    command: CommandResponse::Response,
                });
                data.acknowledge_pending = false;
            }
            return actions;
        }

        if p.ns == data.vr {
            debug!("rax25: iframe in order {}", p.ns);
            // Frame is in order.
            data.vr = (data.vr + 1) % data.modulus.as_u8();
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
                data.vr = (data.vr + 1) % data.modulus.as_u8();
            }
            if p.poll.is_set() {
                actions.push(Action::SendRr {
                    pf: PollFinal::Set,
                    nr: data.vr,
                    command: CommandResponse::Response,
                });
                data.acknowledge_pending = false;
                return actions;
            }
            if !data.acknowledge_pending {
                // LM seize request (?).
                data.acknowledge_pending = true;
            }
            return actions;
        }
        debug!("Iframe not in order got={} want={}", p.ns, data.vr);
        if data.reject_exception {
            // discard frame (implicit)
            if p.poll.is_set() {
                actions.push(Action::SendRr {
                    pf: PollFinal::Set,
                    nr: data.vr,
                    command: CommandResponse::Response,
                });
                data.acknowledge_pending = false;
            }
            return actions;
        }
        if !data.srej_enabled {
            // discard iframe (implicit)
            //
            // TODO: should we maybe wait a bit with sending a REJ?
            // Empirically I got a bunch of duplicated packets, and
            // that just wrecks havoc with retransmits.
            //
            // Maybe skip a duplicate?
            data.reject_exception = true;
            actions.push(Action::SendRej {
                pf: p.poll,
                nr: data.vr,
            });
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
        if p.ns != (data.vr + 1) % data.modulus.as_u8() {
            // discard iframe (implicit)
            actions.push(Action::SendRej {
                pf: p.poll,
                nr: data.vr,
            });
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
        data.t1.stop();
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
            // 1998 spec (page 99) doesn't say if it should be true or false.
            // 2017 spec adds that pf should be false.
            Action::SendDm {
                pf: PollFinal::Clear,
            },
            Action::State(Box::new(Disconnected::new())),
        ]
    }

    // Page 93 (Connected only).
    fn t3(&self, data: &mut Data) -> Vec<Action> {
        data.t3.stop();
        if let ConnectedState::TimerRecovery = self.connected_state {
            error!("T3 should not be running in TimerRecovery");
        }
        // 1998 bug: Says to set rc=0. Fixed in 2017.
        data.rc = 1;
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
    fn ui(&self, data: &mut Data, cr: CommandResponse, packet: &Ui) -> Vec<Action> {
        let mut act = data.ui_check(cr, packet.payload.len());
        if packet.push.is_set() {
            act.push(data.enquiry_response(PollFinal::Set));
        }
        act
    }

    fn rr(&self, data: &mut Data, packet: &Rr, cr: CommandResponse) -> Vec<Action> {
        match self.connected_state {
            ConnectedState::Connected => self.rr_connected(data, packet, cr),
            ConnectedState::TimerRecovery => self.rr_timer_recovery(data, packet, cr),
        }
    }

    // 6.4.7: acknowledge through N(R), then go back and resend the remainder.
    //
    // 1998: Page 96 (Connected) and 100 (TimerRecovery).
    fn rej(&self, data: &mut Data, packet: &Rej, command: CommandResponse) -> Vec<Action> {
        data.peer_receiver_busy = false;
        if !in_range(data.va, packet.nr, data.vs, data.modulus) {
            let mut actions = data.nr_error_recovery();
            actions.push(Action::State(Box::new(AwaitingConnection::new())));
            return actions;
        }
        let mut actions = if command.is_command() && packet.poll.is_set() {
            vec![data.enquiry_response(PollFinal::Set)]
        } else {
            vec![]
        };
        // Do not flush new application data until the rejected frames are resent.
        while data.va != packet.nr {
            data.iframe_resend_queue.pop_front();
            data.va = (data.va + 1) % data.modulus.as_u8();
        }
        data.t1.stop();
        data.rc = 0;
        data.select_t1_value();
        actions.extend(data.invoke_retransmission(packet.nr));
        data.acknowledge_pending = false;
        if data.va == data.vs {
            data.t3.start(data.t3v);
        } else {
            data.t3.stop();
            data.t1.start(data.t1v);
        }
        if matches!(self.connected_state, ConnectedState::TimerRecovery)
            && command.is_response()
            && packet.poll.is_set()
        {
            actions.push(Action::State(Box::new(Self::new(
                ConnectedState::Connected,
            ))));
        }
        actions.extend(data.flush());
        actions
    }
}

/// Ugly range checker.
///
/// if va steps forward, will it hit nr before it hits vs?
#[must_use]
fn in_range(va: u8, nr: u8, vs: u8, modulus: Modulus) -> bool {
    let mut t = va;
    loop {
        if t == nr {
            return true;
        }
        if t == vs {
            return false;
        }
        t = (t + 1) % modulus.as_u8();
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

fn abort_missing_peer(
    data: &mut Data,
    mut events: Vec<ReturnEvent>,
) -> (Option<Box<dyn State>>, Vec<ReturnEvent>) {
    error!("Outgoing frame has no peer; closing the connection");
    data.t1.stop();
    data.t3.stop();
    data.management.stop();
    data.clear_iframe_queue();
    data.obuf.clear();
    events.push(ReturnEvent::Data(Res::EOF));
    (Some(Box::new(Disconnected::new())), events)
}

/// Handle an incoming state, by shoving it through the state machine.
///
/// Source and destination address are assumed to be correct, or in the case of
/// SABM(E), the address is passed along.
///
/// A set of return events and possibly a new state is returned.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn handle(
    state: &dyn State,
    data: &mut Data,
    packet: &Event,
) -> (Option<Box<dyn State>>, Vec<ReturnEvent>) {
    let actions = match packet {
        Event::Connect { addr, ext } => state.connect(data, addr, *ext),
        Event::ConnectWithXid { addr, ext } => {
            if state.is_state_disconnected() {
                data.start_xid(addr, *ext)
            } else {
                vec![]
            }
        }
        Event::ManagementTimeout => {
            if !data.management.running {
                vec![]
            } else if let Some(config) = &data.xid_config
                && data.management_retries < config.management_retries
            {
                data.management_retries += 1;
                data.management.start(config.management_timeout);
                vec![data.xid_command()]
            } else {
                data.finish_xid(None)
            }
        }
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
        Event::Rej(p, command) => state.rej(data, p, *command),
        Event::Srej(p) => state.srej(data, p),
        Event::Xid(p, command, peer) => {
            if state.is_state_disconnected() || data.management.running {
                data.receive_xid(p, *command, peer)
            } else {
                vec![]
            }
        }
        Event::Test(p, command) => state.test(data, p, *command),
    };
    let mut ret = Vec::new();

    // Save non-state actions.
    for act in &actions {
        #[allow(clippy::enum_glob_use)]
        use Action::*;
        match act {
            Action::State(_) => {} // Ignore state change at this stage.
            SendXid { peer, command, xid } => ret.push(ReturnEvent::Packet(Packet::xid(
                data.me.clone(),
                peer.clone(),
                *command,
                xid.poll,
                xid.parameters.clone(),
            ))),
            DlError(code) => ret.push(ReturnEvent::DlError(*code)),
            // U frames.
            SendSabm { pf } => {
                let Some(ref peer) = data.peer else {
                    return abort_missing_peer(data, ret);
                };
                ret.push(ReturnEvent::Packet(Packet {
                    src: crate::Addr::from(data.me.clone()).with_highbit(false),
                    dst: Addr::from(peer.clone()).with_highbit(true),
                    // Always command per 4.3.3.
                    digipeater: vec![],
                    modulus: data.modulus,
                    packet_type: PacketType::Sabm(Sabm { poll: *pf }),
                }));
            }
            SendDisc { pf } => {
                let Some(ref peer) = data.peer else {
                    return abort_missing_peer(data, ret);
                };
                ret.push(ReturnEvent::Packet(Packet {
                    src: crate::Addr::from(data.me.clone()).with_highbit(false),
                    dst: Addr::from(peer.clone()).with_highbit(true),
                    // Always command per 4.3.3.
                    digipeater: vec![],
                    modulus: data.modulus,
                    packet_type: PacketType::Disc(Disc { poll: *pf }),
                }));
            }
            SendUa { pf } => {
                let Some(ref peer) = data.peer else {
                    return abort_missing_peer(data, ret);
                };
                ret.push(ReturnEvent::Packet(Packet {
                    src: crate::Addr::from(data.me.clone()).with_highbit(true),
                    dst: Addr::from(peer.clone()).with_highbit(false),
                    // Always response per 4.3.3.
                    digipeater: vec![],
                    modulus: data.modulus,
                    packet_type: PacketType::Ua(Ua { poll: *pf }),
                }));
            }
            SendDm { pf } => {
                let Some(ref peer) = data.peer else {
                    return abort_missing_peer(data, ret);
                };
                ret.push(ReturnEvent::Packet(Packet {
                    src: crate::Addr::from(data.me.clone()).with_highbit(true),
                    dst: Addr::from(peer.clone()).with_highbit(false),
                    // Always response per 4.3.3.
                    digipeater: vec![],
                    modulus: data.modulus,
                    packet_type: PacketType::Dm(Dm { poll: *pf }),
                }));
            }
            // S frames.
            SendRej { pf, nr } => {
                let Some(ref peer) = data.peer else {
                    return abort_missing_peer(data, ret);
                };
                ret.push(ReturnEvent::Packet(Packet {
                    src: crate::Addr::from(data.me.clone()).with_highbit(true),
                    dst: Addr::from(peer.clone()).with_highbit(false),
                    // TODO: REJ can be commands, in status probes.
                    digipeater: vec![],
                    modulus: data.modulus,
                    packet_type: PacketType::Rej(Rej { poll: *pf, nr: *nr }),
                }));
            }
            SendRr { pf, nr, command } => {
                let Some(ref peer) = data.peer else {
                    return abort_missing_peer(data, ret);
                };
                ret.push(ReturnEvent::Packet(Packet {
                    src: crate::Addr::from(data.me.clone()).with_highbit(command.is_response()),
                    dst: Addr::from(peer.clone()).with_highbit(command.is_command()),
                    digipeater: vec![],
                    modulus: data.modulus,
                    packet_type: PacketType::Rr(Rr { poll: *pf, nr: *nr }),
                }));
            }
            SendRnr { pf, nr, command } => {
                let Some(ref peer) = data.peer else {
                    return abort_missing_peer(data, ret);
                };
                ret.push(ReturnEvent::Packet(Packet {
                    src: crate::Addr::from(data.me.clone()).with_highbit(command.is_response()),
                    dst: Addr::from(peer.clone()).with_highbit(command.is_command()),
                    digipeater: vec![],
                    modulus: data.modulus,
                    packet_type: PacketType::Rnr(Rnr { poll: *pf, nr: *nr }),
                }));
            }
            // I frame.
            SendIframe(iframe) => {
                let Some(ref peer) = data.peer else {
                    return abort_missing_peer(data, ret);
                };
                ret.push(ReturnEvent::Packet(Packet {
                    src: crate::Addr::from(data.me.clone()).with_highbit(false),
                    dst: Addr::from(peer.clone()).with_highbit(true),
                    // 4.3.1 seems to say that all I frames are commands.
                    //
                    // TODO: confirm this.
                    digipeater: vec![],
                    modulus: data.modulus,
                    packet_type: PacketType::Iframe(iframe.clone()),
                }));
            }
            // TODO: can we avoid the copy?
            Deliver(p) => ret.push(ReturnEvent::Data(Res::Some(p.clone()))),
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

    #[test]
    fn missing_peer_terminates_and_preserves_prior_events() -> Result<()> {
        struct BrokenState;
        impl State for BrokenState {
            fn name(&self) -> String {
                "Broken".to_string()
            }
            fn t1(&self, _data: &mut Data) -> Vec<Action> {
                vec![
                    Action::DlError(DlError::A),
                    Action::SendDisc { pf: PollFinal::Set },
                    Action::State(Box::new(Connected::new(ConnectedState::Connected))),
                ]
            }
        }
        let mut data = Data::new(Callsign::new("LOCAL")?);
        data.t1.start(std::time::Duration::from_secs(60));
        data.t3.start(std::time::Duration::from_secs(60));
        data.management.start(std::time::Duration::from_secs(60));
        let (state, events) = handle(&BrokenState, &mut data, &Event::T1);
        assert!(state.is_some_and(|state| state.is_state_disconnected()));
        assert_eq!(
            events,
            [
                ReturnEvent::DlError(DlError::A),
                ReturnEvent::Data(Res::EOF)
            ]
        );
        assert!(!data.t1.running);
        assert!(!data.t3.running);
        assert!(!data.management.running);
        Ok(())
    }

    #[test]
    fn clearing_xid_config_stops_retries_and_ignores_stale_timeout() -> Result<()> {
        let mut data = Data::new(Callsign::new("LOCAL")?);
        let peer = Callsign::new("REMOTE")?;
        let request = Xid {
            poll: PollFinal::Set,
            parameters: Some(XidConfig::default().offer(false)),
        };
        data.receive_xid(&request, CommandResponse::Command, &peer);
        assert_eq!(data.pending_xid.len(), 1);
        data.start_xid(&peer, None);
        assert!(data.management.running);
        data.clear_xid_config();
        assert!(!data.management.running);
        assert!(data.xid_config.is_none());
        assert_eq!(data.pending_xid, VecDeque::new());
        let (state, events) = handle(&AwaitingXid, &mut data, &Event::ManagementTimeout);
        assert!(state.is_none());
        assert_eq!(events, []);
        let (state, _) = handle(&AwaitingXid, &mut data, &Event::Disconnect);
        assert!(state.is_some_and(|state| state.is_state_disconnected()));
        Ok(())
    }

    #[test]
    fn xid_timeout_without_config_falls_back() -> Result<()> {
        let mut data = Data::new(Callsign::new("LOCAL")?);
        data.start_xid(&Callsign::new("REMOTE")?, Some(true));
        data.xid_config = None;
        let (state, events) = handle(&AwaitingXid, &mut data, &Event::ManagementTimeout);
        assert!(state.is_some_and(|state| state.name() == "AwaitingConnection"));
        assert!(!data.management.running);
        assert!(!data.ext());
        assert!(matches!(events.as_slice(), [ReturnEvent::Packet(_)]));
        Ok(())
    }

    #[test]
    fn accepted_data_transfers_only_matching_live_proposal() -> Result<()> {
        let mut listener = Data::new(Callsign::new("LOCAL")?);
        let peer = Callsign::new("REMOTE")?;
        let other = Callsign::new("OTHER")?;
        let stale = Callsign::new("STALE")?;
        let request = Xid {
            poll: PollFinal::Set,
            parameters: Some(XidConfig::default().offer(false)),
        };
        for station in [&peer, &other, &stale] {
            listener.receive_xid(&request, CommandResponse::Command, station);
        }
        assert_eq!(listener.pending_xid.len(), 3);
        listener.pending_xid[2].2 = std::time::Instant::now();
        let proposal = listener.pending_xid[0].clone();
        let unrelated = listener.pending_xid[1].clone();

        let accepted = listener.accepted_data(&peer);
        assert_eq!(accepted.pending_xid, VecDeque::from([proposal]));
        assert_eq!(listener.pending_xid, VecDeque::from([unrelated.clone()]));
        assert_eq!(listener.accepted_data(&peer).pending_xid, VecDeque::new());
        assert_eq!(listener.pending_xid, VecDeque::from([unrelated]));
        Ok(())
    }

    #[test]
    fn accepted_connection_inherits_linux_hint_policy() -> Result<()> {
        let mut listener = Data::new(Callsign::new("LOCAL")?);
        let peer = Callsign::new("REMOTE")?;
        assert!(listener.linux_extended_hint);
        for enabled in [false, true] {
            listener.set_linux_extended_hint(enabled);
            assert_eq!(listener.accepted_data(&peer).linux_extended_hint, enabled);
        }
        Ok(())
    }

    #[test]
    fn outgoing_packets_carry_connection_mode() -> Result<()> {
        for extended in [false, true] {
            let mut data = Data::new(Callsign::new("LOCAL")?);
            let (state, setup) = handle(
                &*new(),
                &mut data,
                &Event::Connect {
                    addr: Callsign::new("REMOTE")?,
                    ext: extended,
                },
            );
            let (state, _) = handle(
                &*state.unwrap(),
                &mut data,
                &Event::Ua(Ua {
                    poll: PollFinal::Set,
                }),
            );
            let connected = state.unwrap();
            let (_, frames) = handle(&*connected, &mut data, &Event::Data(b"hello".to_vec()));
            let (_, poll) = handle(&*connected, &mut data, &Event::T3);
            let (_, disconnect) = handle(&*connected, &mut data, &Event::Disconnect);
            for events in [setup, frames, poll, disconnect] {
                let packets: Vec<_> = events
                    .iter()
                    .filter_map(|event| {
                        if let ReturnEvent::Packet(packet) = event {
                            Some(packet)
                        } else {
                            None
                        }
                    })
                    .collect();
                assert_eq!(packets.len(), 1);
                for packet in packets {
                    assert_eq!(packet.modulus.is_extended(), extended);
                    let bytes = packet.serialize();
                    assert_eq!(bytes[13] & 0x40 == 0, extended);
                    assert_eq!(Packet::parse(&bytes, None)?.modulus, packet.modulus);
                    let event = ReturnEvent::Packet(packet.clone());
                    assert_eq!(event.serialize(), Some(bytes.clone()));
                    let mut without_hint = bytes;
                    without_hint[13] |= 0x40;
                    assert_eq!(
                        event.serialize_with_linux_extended_hint(false),
                        Some(without_hint)
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn xid_requires_final_and_selected_mode() -> Result<()> {
        let mut data = Data::new(Callsign::new("LOCAL")?);
        let peer = Callsign::new("REMOTE")?;
        let config = XidConfig::default();
        data.set_xid_config(config.clone());
        data.start_xid(&peer, Some(true));
        assert!(
            data.receive_xid(
                &Xid {
                    poll: PollFinal::Clear,
                    parameters: Some(config.offer(true))
                },
                CommandResponse::Response,
                &peer
            )
            .is_empty()
        );
        assert!(data.management.running);
        data.receive_xid(
            &Xid {
                poll: PollFinal::Set,
                parameters: Some(config.offer(false)),
            },
            CommandResponse::Response,
            &peer,
        );
        assert!(!data.management.running);
        assert!(!data.ext());
        assert!(data.negotiated.is_none());
        Ok(())
    }

    #[test]
    fn xid_proposals_are_bounded_expire_and_do_not_lock_peer() -> Result<()> {
        let mut data = Data::new(Callsign::new("LOCAL")?);
        data.able_to_establish = true;
        let packet = Xid {
            poll: PollFinal::Set,
            parameters: Some(XidConfig::default().offer(false)),
        };
        for index in 0..17 {
            let peer = Callsign::new(format!("P{index:02}"))?;
            assert!(
                !data
                    .receive_xid(&packet, CommandResponse::Command, &peer)
                    .is_empty()
            );
        }
        assert_eq!(data.pending_xid.len(), 16);
        assert!(data.peer.is_none());
        assert_eq!(data.pending_xid.front().unwrap().0.call(), "P01");
        for (_, _, expiry) in &mut data.pending_xid {
            *expiry = std::time::Instant::now();
        }
        data.expire_pending_xid();
        assert!(data.pending_xid.is_empty());
        Ok(())
    }

    #[test]
    fn crossed_xid_commands_leave_outstanding_exchange_active() -> Result<()> {
        let mut data = Data::new(Callsign::new("LOCAL")?);
        let peer = Callsign::new("REMOTE")?;
        data.start_xid(&peer, None);
        let packet = Xid {
            poll: PollFinal::Set,
            parameters: Some(XidConfig::default().offer(true)),
        };
        assert!(
            !data
                .receive_xid(&packet, CommandResponse::Command, &peer)
                .is_empty()
        );
        assert!(data.management.running);
        assert!(data.negotiated.is_none());
        data.receive_xid(&packet, CommandResponse::Response, &peer);
        assert!(!data.management.running);
        assert!(data.ext());
        assert!(data.negotiated.is_some());
        Ok(())
    }

    #[test]
    fn rej_retires_acknowledged_frames_and_resends_remaining() -> Result<()> {
        let mut data = Data::new(Callsign::new("LOCAL")?);
        data.vs = 2;
        for ns in 0..2 {
            data.iframe_resend_queue.push_back(Iframe {
                ns,
                nr: 0,
                poll: PollFinal::Clear,
                pid: 0xf0,
                payload: vec![ns],
            });
        }
        let connected = Connected::new(ConnectedState::Connected);
        let actions = connected.rej(
            &mut data,
            &Rej {
                poll: PollFinal::Clear,
                nr: 1,
            },
            CommandResponse::Response,
        );
        assert_eq!(data.va, 1);
        assert_eq!(data.iframe_resend_queue.len(), 1);
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, Action::SendIframe(frame) if frame.ns == 1))
        );
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, Action::SendIframe(frame) if frame.ns == 0))
        );
        Ok(())
    }

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
        let mut data = Data::new(Callsign::new("M0THC-1")?);
        let con = Disconnected::new();

        // First attempt.
        dbg!("First attempt");
        let (con, events) = handle(
            &con,
            &mut data,
            &Event::Connect {
                addr: Callsign::new("M0THC-2")?,
                ext: false,
            },
        );
        let con = con.unwrap();
        assert_eq!(con.name(), "AwaitingConnection");
        assert_eq!(data.peer, Some(Callsign::new("M0THC-2")?));
        assert_all(
            &[ReturnEvent::Packet(Packet {
                src: crate::Addr::from(Callsign::new("M0THC-1")?).with_highbit(false),
                dst: crate::Addr::from(Callsign::new("M0THC-2")?).with_highbit(true),
                digipeater: vec![],
                modulus: Modulus::Standard,
                packet_type: PacketType::Sabm(Sabm {
                    poll: PollFinal::Set,
                }),
            })],
            &events,
            "connect",
        );

        for retry in 1.. {
            dbg!("Retry", retry);
            let (c2, events) = handle(&*con, &mut data, &Event::T1);
            if retry == 10 {
                assert_eq!(c2.unwrap().name(), "Disconnected");
                break;
            }
            assert!(c2.is_none());
            assert_eq!(data.peer, Some(Callsign::new("M0THC-2")?));
            assert_all(
                &[ReturnEvent::Packet(Packet {
                    src: crate::Addr::from(Callsign::new("M0THC-1")?).with_highbit(false),
                    dst: crate::Addr::from(Callsign::new("M0THC-2")?).with_highbit(true),
                    digipeater: vec![],
                    modulus: Modulus::Standard,
                    packet_type: PacketType::Sabm(Sabm {
                        poll: PollFinal::Set,
                    }),
                })],
                &events,
                "connect",
            );
        }
        Ok(())
    }

    #[test]
    fn disconnected_incoming() -> Result<()> {
        let mut data = Data::new(Callsign::new("M0THC-1")?);
        data.able_to_establish = true; // TODO: implement some sort of listen()
        let con = Disconnected::new();

        let (con, events) = handle(
            &con,
            &mut data,
            &Event::Sabm(
                Sabm {
                    poll: PollFinal::Set,
                },
                Callsign::new("M0THC-2")?,
            ),
        );
        let con = con.unwrap();
        assert_eq!(con.name(), "Connected");
        assert_eq!(data.peer, Some(Callsign::new("M0THC-2")?));
        assert_all(
            &[ReturnEvent::Packet(Packet {
                src: crate::Addr::from(Callsign::new("M0THC-1")?).with_highbit(true),
                dst: crate::Addr::from(Callsign::new("M0THC-2")?).with_highbit(false),
                digipeater: vec![],
                modulus: Modulus::Standard,
                packet_type: PacketType::Ua(Ua {
                    poll: PollFinal::Set,
                }),
            })],
            &events,
            "connect",
        );
        Ok(())
    }

    #[test]
    fn connected() -> Result<()> {
        let mut data = Data::new(Callsign::new("M0THC-1")?);
        data.peer = Some(Callsign::new("M0THC-2")?);
        let con = Connected::new(ConnectedState::Connected);

        eprintln!("Receive data packet");
        let (c2, events) = handle(
            &con,
            &mut data,
            &Event::Iframe(
                Iframe {
                    nr: 0,
                    ns: 0,
                    poll: PollFinal::Set, // TODO: poll or no?
                    pid: 0xF0,
                    payload: vec![1, 2, 3],
                },
                CommandResponse::Command,
            ),
        );
        assert!(c2.is_none());
        assert_all(
            &[
                ReturnEvent::Data(Res::Some(vec![1, 2, 3])),
                ReturnEvent::Packet(Packet {
                    src: crate::Addr::from(Callsign::new("M0THC-1")?).with_highbit(true),
                    dst: crate::Addr::from(Callsign::new("M0THC-2")?).with_highbit(false),
                    digipeater: vec![],
                    modulus: Modulus::Standard,
                    packet_type: PacketType::Rr(Rr {
                        poll: PollFinal::Set,
                        nr: 1,
                    }),
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
                    poll: PollFinal::Set, // TODO: poll or no?
                    pid: 0xF0,
                    payload: vec![1, 2, 3],
                },
                CommandResponse::Command,
            ),
        );
        assert!(c2.is_none());
        assert_all(
            &[ReturnEvent::Packet(Packet {
                src: crate::Addr::from(Callsign::new("M0THC-1")?).with_highbit(true),
                dst: crate::Addr::from(Callsign::new("M0THC-2")?).with_highbit(false),
                digipeater: vec![],
                modulus: Modulus::Standard,
                packet_type: PacketType::Rej(Rej {
                    poll: PollFinal::Set,
                    nr: 1,
                }),
            })],
            &events,
            "iframe",
        );

        eprintln!("Receive next packet");
        let (c2, events) = handle(
            &con,
            &mut data,
            &Event::Iframe(
                Iframe {
                    nr: 0,
                    ns: 1,
                    poll: PollFinal::Set, // TODO: poll or no?
                    pid: 0xF0,
                    payload: vec![11, 22, 33],
                },
                CommandResponse::Command,
            ),
        );
        assert!(c2.is_none());
        assert_all(
            &[
                ReturnEvent::Data(Res::Some(vec![11, 22, 33])),
                ReturnEvent::Packet(Packet {
                    src: crate::Addr::from(Callsign::new("M0THC-1")?).with_highbit(true),
                    dst: crate::Addr::from(Callsign::new("M0THC-2")?).with_highbit(false),
                    digipeater: vec![],
                    modulus: Modulus::Standard,
                    packet_type: PacketType::Rr(Rr {
                        poll: PollFinal::Set,
                        nr: 2,
                    }),
                }),
            ],
            &events,
            "iframe",
        );
        Ok(())
    }

    #[test]
    fn disconnect() -> Result<()> {
        let mut data = Data::new(Callsign::new("M0THC-1")?);
        data.peer = Some(Callsign::new("M0THC-2")?);
        let con = Connected::new(ConnectedState::Connected);
        let (c2, events) = handle(
            &con,
            &mut data,
            &Event::Disc(Disc {
                poll: PollFinal::Set,
            }),
        );
        assert_eq!(c2.unwrap().name(), "Disconnected");
        assert_all(
            &[
                ReturnEvent::Data(Res::EOF),
                ReturnEvent::Packet(Packet {
                    src: crate::Addr::from(Callsign::new("M0THC-1")?).with_highbit(true),
                    dst: crate::Addr::from(Callsign::new("M0THC-2")?).with_highbit(false),
                    digipeater: vec![],
                    modulus: Modulus::Standard,
                    packet_type: PacketType::Ua(Ua {
                        poll: PollFinal::Set,
                    }),
                }),
            ],
            &events,
            "disconnect",
        );
        Ok(())
    }
}
/* vim: textwidth=80
 */
