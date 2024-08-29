use crate::{Addr, Disc, Dm, Iframe, Packet, PacketType, Rnr, Rr, Sabm, Sabme, Ua, Ui};
use anyhow::Result;
use log::debug;
use std::collections::VecDeque;

// Incoming events to the state machine.
#[derive(Debug, PartialEq)]
pub enum Event {
    Connect(Addr),
    Disconnect,
    Data(Vec<u8>),
    T1,
    T3,
    Sabm(Sabm, Addr),
    Sabme(Sabme, Addr),
    Dm(Dm),
    Rr(Rr, bool),
    Ui(Ui, bool),
    Disc(Disc),
    Iframe(Iframe, bool),
    Ua(Ua),
}

// Return events, that the state machine wants to tell the world. IOW excludes state changes.
#[derive(Debug, PartialEq)]
pub enum ReturnEvent {
    Packet(Packet),
    DlError(DlError),
    Data(Res),
}

impl ReturnEvent {
    // Not very clean. Only packets can serialize.
    pub fn serialize(&self) -> Option<Vec<u8>> {
        match self {
            ReturnEvent::Packet(p) => Some(p.serialize()),
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

// Errors. TODO: implement stringifications of these.
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
                DlError::C => "C: Unexpected UA in states 3,4,5",
                DlError::D => "D: UA received without F=1 when SABM or DISC was sent P=1",
                DlError::E => "E: DM received in states 3,4,5",
                DlError::F => "F: Data link reset; i.e., SABM received instate 3,4,5",
                DlError::G => "G: Connection timed out", // TODO: specs don't list ths.
                DlError::H => "H: Undocumented?",
                DlError::I => "I: N2 timeouts; unacknowledged data",
                DlError::J => "J: N(r) sequence error",
                DlError::K => "K: Undocumented?",
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

// Actions are like ReturnEvent, except packets are separate.
// Terminology here is not very great.
pub enum Action {
    State(Box<dyn State>),
    DlError(DlError),
    SendUa(bool),
    SendRr(bool, u8, bool),
    SendRnr(bool, u8),
    SendDisc(bool),
    SendIframe(Iframe),
    SendDm(bool),
    SendSabm(bool),
    Deliver(Vec<u8>),
    EOF,
}

// Spec says 3s.
const DEFAULT_SRT: std::time::Duration = std::time::Duration::from_secs(1);

const DEFAULT_N2: u8 = 3;

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
    fn start(&mut self, v: std::time::Duration) {
        self.expiry = std::time::Instant::now() + v;
        self.running = true;
    }
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
        Some(self.expiry - std::time::Instant::now())
    }
    fn stop(&mut self) {
        self.running = false;
    }
    fn restart(&mut self, v: std::time::Duration) {
        self.start(v); // TODO: is start and restart the same thing?
    }
}

#[derive(Debug)]
pub struct Data {
    me: Addr,

    peer: Option<Addr>,
    // TODO: double check all types.
    layer3_initiated: bool,
    t1: Timer,
    t3: Timer,
    t3v: std::time::Duration, // TODO: is this where the init value should be?
    vs: u8,
    va: u8,
    vr: u8,
    pub(crate) srt_default: std::time::Duration,
    srt: std::time::Duration,
    t1v: std::time::Duration,
    n1: u32,
    n2: u8,
    rc: u8,
    modulus: u8,
    peer_receiver_busy: bool,
    reject_exception: bool,
    sreject_exception: u32,
    own_receiver_busy: bool,
    acknowledge_pending: bool,
    srej_enabled: bool,
    k: u8,

    // TODO: not the right type.
    iframe_queue: Vec<Vec<u8>>,
    iframe_resend_queue: VecDeque<Iframe>,
}

impl Data {
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
            t3v: std::time::Duration::from_secs(1), // TODO
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
            iframe_resend_queue: VecDeque::new(),
        }
    }
    pub fn t1_expired(&self) -> bool {
        self.t1.is_expired().unwrap_or(false)
    }
    pub fn t3_expired(&self) -> bool {
        self.t3.is_expired().unwrap_or(false)
    }
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

    pub fn next_timer_remaining(&self) -> Option<std::time::Duration> {
        match (self.t1.remaining(), self.t3.remaining()) {
            (Some(t1), Some(t3)) => Some(std::cmp::min(t1, t3)),
            (None, Some(t)) => Some(t),
            (Some(t), None) => Some(t),
            (None, None) => None,
        }
    }

    // Page 106.
    fn nr_error_recovery(&mut self) -> Vec<Action> {
        self.layer3_initiated = false;
        vec![Action::DlError(DlError::J), self.establish_data_link()]
    }

    // Page 108.
    fn check_need_for_response(&mut self, command: bool, pf: bool) -> Vec<Action> {
        if command && pf {
            vec![self.enquiry_response(true)]
        } else if !command && pf {
            vec![Action::DlError(DlError::A)]
        } else {
            vec![]
        }
    }

    // Page 106.
    fn enquiry_response(&mut self, f: bool) -> Action {
        self.acknowledge_pending = false;
        if self.own_receiver_busy {
            Action::SendRnr(f, self.vr)
        } else {
            Action::SendRr(f, self.vr, false)
        }
    }

    // Page 109.
    fn select_t1_value(&mut self) {
        if self.rc == 0 {
            // TODO: the real formula is stranger.
            self.srt = self.srt_default;
        } else if self.t1_expired() {
            // TODO: spec unclear, default to exponential.
            self.srt = self.srt + self.srt;
        }
    }

    // Page 106.
    fn transmit_enquiry(&mut self) -> Action {
        self.acknowledge_pending = false;
        self.t1.start(self.t1v); // TODO: what timer value?
        if self.own_receiver_busy {
            Action::SendRnr(true, self.vr)
        } else {
            Action::SendRr(true, self.vr, true)
        }
    }
    // Page 107.
    fn check_iframe_acked(&mut self, nr: u8) {
        if self.peer_receiver_busy {
            // Typo in spec. Says "peer busy".
            self.update_ack(nr);
            self.t3.start(self.t3v);
            if !self.t1.running {
                self.t1.start(self.srt); // srt or t1v?
            }
            return;
        }
        if nr == self.vs {
            self.update_ack(nr);
            self.t1.stop();
            self.t3.start(self.t3v);
            self.select_t1_value();
            return;
        }
        if nr != self.va {
            self.update_ack(nr);
            self.t1.restart(self.srt);
        }
    }
    fn update_ack(&mut self, nr: u8) {
        // dbg!(self.va, nr);
        while self.va != nr {
            assert!(!self.iframe_resend_queue.is_empty());
            self.iframe_resend_queue.pop_front();
            self.va = (self.va + 1) % self.modulus;
        }
    }
    fn clear_iframe_queue(&mut self) {
        self.iframe_queue.clear();
        self.iframe_resend_queue.clear();
    }
    fn clear_exception_conditions(&mut self) {
        self.peer_receiver_busy = false;
        self.reject_exception = false;
        self.own_receiver_busy = false;
        self.acknowledge_pending = false;
    }

    // Page 106.
    fn establish_data_link(&mut self) -> Action {
        self.clear_exception_conditions();
        self.rc = 0;
        self.t3.stop();
        self.t1.restart(self.srt); // TODO
        Action::SendSabm(true)
    }

    // Page 109.
    fn set_version_2_2(&mut self) {
        // TODO: set half duplex SREJ
        self.modulus = 128;
        // TODO: n1r = 2048
        // TODO: kr = 4
        // TODO: self.t2.set(3000);
        self.n2 = 10;
    }

    // Page 109.
    fn set_version_2(&mut self) {
        self.modulus = 8;
        // TODO: n1r = 2048
        // TODO: kr = 32
        // TODO: self.t2.set(3000);
        self.n2 = 10;
    }
}

pub trait State {
    fn name(&self) -> String;
    fn connect(&self, _data: &mut Data, _addr: &Addr) -> Vec<Action> {
        eprintln!("TODO: unexpected DLConnect");
        vec![]
    }
    fn disconnect(&self, _data: &mut Data) -> Vec<Action> {
        eprintln!("TODO: unexpected DLDisconnect in state {}", self.name());
        vec![]
    }
    fn data(&self, _data: &mut Data, _payload: &[u8]) -> Vec<Action> {
        eprintln!("writing data while not connected!");
        vec![]
    }
    fn t1(&self, _data: &mut Data) -> Vec<Action> {
        eprintln!("TODO: unexpected T1 expire");
        vec![]
    }
    fn t3(&self, _data: &mut Data) -> Vec<Action> {
        eprintln!("TODO: unexpected T3 expire");
        vec![]
    }
    fn frmr(&self, _data: &mut Data) -> Vec<Action> {
        eprintln!("TODO: unexpected FRMR");
        vec![]
    }
    fn rr(&self, _data: &mut Data, _packet: &Rr, _command: bool) -> Vec<Action> {
        eprintln!("TODO: unexpected RR");
        vec![]
    }
    fn sabm(&self, _data: &mut Data, _src: &Addr, _packet: &Sabm) -> Vec<Action> {
        eprintln!("TODO: unexpected SABM");
        vec![]
    }
    fn sabme(&self, _data: &mut Data, _src: &Addr, _packet: &Sabme) -> Vec<Action> {
        eprintln!("TODO: unexpected SABME");
        vec![]
    }
    fn iframe(&self, _data: &mut Data, _packet: &Iframe, _cr: bool) -> Vec<Action> {
        eprintln!("TODO; unexpected iframe");
        vec![]
    }
    fn ui(&self, _data: &mut Data, _cr: bool, _packet: &Ui) -> Vec<Action> {
        vec![]
    }
    fn ua(&self, _data: &mut Data, _packet: &Ua) -> Vec<Action> {
        eprintln!("TODO; unexpected UA");
        vec![]
    }
    fn dm(&self, _data: &mut Data, _packet: &Dm) -> Vec<Action> {
        eprintln!("TODO: unexpected DM");
        vec![]
    }
    fn disc(&self, _data: &mut Data, _packet: &Disc) -> Vec<Action> {
        eprintln!("TODO: unexpected DISC");
        vec![]
    }
}

// Unnumbered information is pretty uninteresting here.
// Page 108.
fn ui_check(command: bool) -> Vec<Action> {
    if !command {
        return vec![Action::DlError(DlError::Q)];
    }
    if
    /*packet too long*/
    false {
        return vec![Action::DlError(DlError::K)];
    }
    debug!("DL-UNIT_DATA indication");
    vec![]
}

/// Disconnected state.
///
/// I think this is fully implemented for AX.25 2.0. No SABME yet, though.
///
/// This is a state diagram for a connection. Any non-listening socket
/// should in theory cause `SendDm(p.poll)`, but out of scope.
struct Disconnected {}
impl Disconnected {
    pub fn new() -> Self {
        Self {}
    }

    // Page 85.
    fn sabm_and_sabme(&self, data: &mut Data, src: Addr, poll: bool) -> Vec<Action> {
        data.clear_exception_conditions();
        data.vs = 0;
        data.va = 0;
        data.vr = 0;
        data.srt = data.srt_default;
        data.t1v = data.srt + data.srt;
        data.t3.start(data.t3v);
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
    // Page 85.
    fn connect(&self, data: &mut Data, addr: &Addr) -> Vec<Action> {
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
    fn ui(&self, _data: &mut Data, cr: bool, packet: &Ui) -> Vec<Action> {
        let mut ret = ui_check(cr);
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

struct AwaitingConnection {}

impl AwaitingConnection {
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
            // discard frame.
            debug!("DL-CONNECT indiciation"); // huh?
        }
        data.t1.stop();
        data.t3.stop();
        data.vs = 0;
        data.va = 0;
        data.vr = 0;
        vec![Action::State(Box::new(Connected::new(
            ConnectedState::Connected,
        )))]
    }
}

struct AwaitingRelease {}

impl AwaitingRelease {
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
struct Connected {
    connected_state: ConnectedState,
}

impl Connected {
    fn new(connected_state: ConnectedState) -> Self {
        Self { connected_state }
    }
    // Page 95
    fn rr_connected(&self, data: &mut Data, packet: &Rr, cr: bool) -> Vec<Action> {
        data.peer_receiver_busy = false;
        let mut act = data.check_need_for_response(cr, packet.poll);
        if !in_range(data.va, packet.nr, data.vs, data.modulus) {
            data.nr_error_recovery();
            act.push(Action::State(Box::new(AwaitingConnection::new())));
        } else {
            data.check_iframe_acked(packet.nr);
        }
        act
    }
    fn rr_timer_recovery(&self, _data: &mut Data, _packet: &Rr, _cr: bool) -> Vec<Action> {
        eprintln!("TODO: rr_timer_recovery");
        vec![]
    }
}

impl State for Connected {
    fn name(&self) -> String {
        "Connected".to_string()
    }

    // Page 92.
    fn disconnect(&self, data: &mut Data) -> Vec<Action> {
        data.iframe_queue.clear();
        data.rc = 0;
        data.t1.start(data.srt); // TODO: with what timer?
        data.t3.stop();
        vec![
            Action::SendDisc(true),
            Action::State(Box::new(AwaitingRelease::new())),
        ]
    }

    // Page 92.
    // TODO: this sends directly, without putting it on any queue.
    // So really, this is maybe the event "pop iframe".
    fn data(&self, data: &mut Data, payload: &[u8]) -> Vec<Action> {
        if data.peer_receiver_busy {
            panic!("TODO: we have no tx queue");
        }
        if data.vs == data.va + data.k {
            panic!("TODO: tx window full!");
        }
        let ns = data.vs;
        data.vs += 1;
        data.acknowledge_pending = false;
        if data.t1.running {
            data.t3.stop();
            data.t1.start(data.srt);
        }
        let i = Iframe {
            ns,
            nr: data.vr,
            poll: false,
            pid: 0xF0,
            payload: payload.to_vec(),
        };
        data.iframe_resend_queue.push_back(i.clone());
        vec![Action::SendIframe(i)]
    }
    // Page 93.
    fn sabm(&self, _data: &mut Data, _src: &Addr, _packet: &Sabm) -> Vec<Action> {
        eprintln!("TODO: Connected: sabm not handled");
        vec![]
    }
    // Page 93.
    fn sabme(&self, _data: &mut Data, _src: &Addr, _packet: &Sabme) -> Vec<Action> {
        eprintln!("TODO: Connected: sabme not handled");
        vec![]
    }

    // Page 93.
    //
    // Done.
    fn dm(&self, data: &mut Data, _packet: &Dm) -> Vec<Action> {
        data.clear_iframe_queue();
        data.t1.stop();
        data.t3.stop();
        vec![
            Action::DlError(DlError::E),
            Action::State(Box::new(Disconnected::new())),
        ]
    }

    // Page 93.
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
            return vec![Action::DlError(DlError::S)];
        }
        if p.payload.len() > data.n1.try_into().unwrap() {
            data.layer3_initiated = false;
            return vec![
                data.establish_data_link(),
                Action::DlError(DlError::O),
                Action::State(Box::new(AwaitingConnection::new())),
            ];
        }
        if !in_range(data.va, p.nr, data.vs, data.modulus) {
            let mut acts = data.nr_error_recovery();
            acts.push(Action::State(Box::new(AwaitingConnection::new())));
            return acts;
        }
        if let ConnectedState::Connected = self.connected_state {
            data.check_iframe_acked(p.nr);
        } else {
            data.update_ack(p.nr);
        }
        if data.own_receiver_busy {
            // discord (implicit)
            if p.poll {
                data.acknowledge_pending = false;
                return vec![Action::SendRnr(true, data.vr)];
            }
            return vec![];
        }

        let mut actions = vec![];
        if p.ns == data.vr {
            data.vr = (data.vr + 1) % data.modulus;
            // TODO: clear reject exception
            // TODO: decrement sreject exception if >0
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
    // Page 93.
    fn t1(&self, data: &mut Data) -> Vec<Action> {
        data.rc = 1;
        vec![
            Action::State(Box::new(Connected::new(ConnectedState::TimerRecovery))),
            data.transmit_enquiry(),
        ]
    }
    // Page 93.
    fn t3(&self, data: &mut Data) -> Vec<Action> {
        data.rc = 0;
        vec![
            Action::State(Box::new(Connected::new(ConnectedState::TimerRecovery))),
            data.transmit_enquiry(),
        ]
    }
    // Page 93.
    fn ua(&self, data: &mut Data, _ua: &Ua) -> Vec<Action> {
        data.layer3_initiated = false;
        vec![
            Action::DlError(DlError::C),
            data.establish_data_link(),
            Action::State(Box::new(AwaitingConnection::new())),
        ]
    }
    // Page 94.
    fn frmr(&self, data: &mut Data) -> Vec<Action> {
        data.layer3_initiated = false;
        vec![
            Action::DlError(DlError::K),
            data.establish_data_link(),
            Action::State(Box::new(AwaitingConnection::new())),
        ]
    }
    // Page 94.
    // TODO: ui

    fn rr(&self, data: &mut Data, packet: &Rr, cr: bool) -> Vec<Action> {
        match self.connected_state {
            ConnectedState::Connected => self.rr_connected(data, packet, cr),
            ConnectedState::TimerRecovery => self.rr_timer_recovery(data, packet, cr),
        }
    }
}

// Ugly range checker.
//
// if va steps forward, will it hit nr before it hits vs?
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

pub fn new() -> Box<dyn State> {
    Box::new(Disconnected::new())
}

#[derive(Debug, PartialEq)]
pub enum Res {
    None,
    EOF,
    Some(Vec<u8>),
}

pub fn handle(
    state: &dyn State,
    data: &mut Data,
    packet: &Event,
) -> (Option<Box<dyn State>>, Vec<ReturnEvent>) {
    let actions = match packet {
        Event::Connect(addr) => state.connect(data, addr),
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
                command_response_la: false, // TODO: set to what?
                digipeater: vec![],
                rr_dist1: false,
                rr_extseq: false,
                packet_type: PacketType::Rr(Rr {
                    poll: *poll,
                    nr: *nr,
                }),
            })),
            SendRnr(poll, nr) => ret.push(ReturnEvent::Packet(Packet {
                src: data.me.clone(),
                dst: data.peer.clone().unwrap().clone(),
                command_response: true,     // TODO: what value?
                command_response_la: false, // TODO: same
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
        let (con, events) = handle(&con, &mut data, &Event::Connect(Addr::new("M0THC-2")?));
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
            if retry == 4 {
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
                    command_response_la: false,
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
                    command_response_la: false,
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
