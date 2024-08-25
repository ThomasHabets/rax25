use crate::{Addr, Disc, Dm, Iframe, Packet, PacketType, Sabm, Sabme, Ua, Ui};

#[derive(Debug, PartialEq)]
pub enum Event {
    Connect(Addr),
    T1,
    T3,
    Sabm(Sabm, Addr),
    Sabme(Sabme, Addr),
    Dm(Dm),
    Ui(Ui, bool),
    Disc(Disc),
    Iframe(Iframe, bool),
    Ua(Ua, bool),
}

#[derive(Debug, PartialEq)]
pub enum ReturnEvent {
    Packet(Packet),
    DlError(DlError),
    Data(Res),
}

impl ReturnEvent {
    pub fn serialize(&self) -> Option<Vec<u8>> {
        match self {
            ReturnEvent::Packet(p) => Some(p.serialize()),
            ReturnEvent::DlError(e) => {
                eprintln!("TODO: DLERROR: {e:?}");
                None
            }
            ReturnEvent::Data(d) => {
                eprintln!("Data received: {d:?}");
                None
            }
        }
    }
}

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

pub enum Action {
    State(Box<dyn State>),
    DlError(DlError),
    SendUa(bool),
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
    own_receiver_busy: bool,
    acknowledge_pending: bool,

    // TODO: not the right type.
    iframe_queue: Vec<Vec<u8>>,
    iframe_resend_queue: Vec<Vec<u8>>,
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
            n2: DEFAULT_N2,
            rc: 0,
            modulus: 8,
            peer_receiver_busy: false,
            reject_exception: false,
            acknowledge_pending: false,
            own_receiver_busy: false,
            iframe_queue: Vec::new(),
            iframe_resend_queue: Vec::new(),
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
        dbg!("TODO: unexpected DLConnect");
        vec![]
    }
    fn disconnect(&self, _data: &mut Data) -> Vec<Action> {
        dbg!("TODO: unexpected DLDisconnect");
        vec![]
    }
    fn t1(&self, _data: &mut Data) -> Vec<Action> {
        dbg!("TODO: unexpected T1 expire");
        vec![]
    }
    fn t3(&self, _data: &mut Data) -> Vec<Action> {
        dbg!("TODO: unexpected T3 expire");
        vec![]
    }
    fn sabm(&self, _data: &mut Data, _src: &Addr, _packet: &Sabm) -> Vec<Action> {
        dbg!("TODO: unexpected SABM");
        vec![]
    }
    fn sabme(&self, _data: &mut Data, _src: &Addr, _packet: &Sabme) -> Vec<Action> {
        dbg!("TODO: unexpected SABME");
        vec![]
    }
    fn iframe(&self, _data: &mut Data, _packet: &Iframe, _cr: bool) -> Vec<Action> {
        dbg!("TODO; unexpected iframe");
        vec![]
    }
    fn ui(&self, _data: &mut Data, _cr: bool, _packet: &Ui) -> Vec<Action> {
        vec![]
    }
    fn ua(&self, _data: &mut Data, _pf: bool, _packet: &Ua) -> Vec<Action> {
        dbg!("TODO; unexpected UA");
        vec![]
    }
    fn dm(&self, _data: &mut Data, _packet: &Dm) -> Vec<Action> {
        dbg!("TODO: unexpected DM");
        vec![]
    }
    fn disc(&self, _data: &mut Data, _packet: &Disc) -> Vec<Action> {
        dbg!("TODO: unexpected DISC");
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
    dbg!("DL-UNIT_DATA indication");
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
        data.t3.start(std::time::Duration::from_secs(1)); // TODO
        data.peer = Some(src);
        vec![
            Action::SendUa(poll),
            Action::State(Box::new(Connected::new())),
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
        dbg!("Disconnect while already disconnected");
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
    fn ua(&self, _data: &mut Data, _p: bool, _packet: &Ua) -> Vec<Action> {
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
        dbg!("t1 expired while connecting, retrying");
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
    fn ua(&self, data: &mut Data, f: bool, _packet: &Ua) -> Vec<Action> {
        if !f {
            return vec![Action::DlError(DlError::D)];
        }
        if data.layer3_initiated {
            dbg!("DL-CONNECT CONFIRM");
        } else if data.vs != data.va {
            // discard frame.
            dbg!("DL-CONNECT indiciation"); // huh?
        }
        data.t1.stop();
        data.t3.stop();
        data.vs = 0;
        data.va = 0;
        data.vr = 0;
        vec![Action::State(Box::new(Connected::new()))]
    }
}

struct Connected {}

impl Connected {
    fn new() -> Self {
        Self {}
    }
}
impl State for Connected {
    fn name(&self) -> String {
        "Connected".to_string()
    }
    // Page 93.
    fn sabm(&self, _data: &mut Data, _src: &Addr, _packet: &Sabm) -> Vec<Action> {
        dbg!("TODO: Connected: sabm not handled");
        vec![]
    }
    // Page 93.
    fn sabme(&self, _data: &mut Data, _src: &Addr, _packet: &Sabme) -> Vec<Action> {
        dbg!("TODO: Connected: sabme not handled");
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
    fn iframe(&self, d: &mut Data, p: &Iframe, command_response: bool) -> Vec<Action> {
        if !command_response {
            return vec![Action::DlError(DlError::S)];
        }
        if p.payload.len() > d.n1.try_into().unwrap() {
            d.layer3_initiated = false;
            return vec![
                d.establish_data_link(),
                Action::DlError(DlError::O),
                Action::State(Box::new(AwaitingConnection::new())),
            ];
        }
        // TODO: more.

        vec![Action::Deliver(p.payload.clone())]
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
        Event::T1 => state.t1(data),
        Event::T3 => state.t3(data),
        Event::Sabm(p, src) => state.sabm(data, src, p),
        Event::Sabme(p, src) => state.sabme(data, src, p),
        Event::Dm(dm) => state.dm(data, dm),
        Event::Ui(p, cr) => state.ui(data, *cr, p),
        Event::Disc(p) => state.disc(data, p),
        Event::Iframe(p, command_response) => state.iframe(data, p, *command_response),
        Event::Ua(p, pf) => state.ua(data, *pf, p),
    };
    let mut ret = Vec::new();

    // Save non-state actions.
    for act in &actions {
        use Action::*;
        match act {
            Action::State(_) => {} // Ignore state change at this stage.
            DlError(code) => ret.push(ReturnEvent::DlError(*code)),
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
            assert!(found, "Did not find {w:?}");
        }
        assert_eq!(
            want.len(),
            got.len(),
            "got and want different lengths for {more}:\nwant: {want:?}\ngot: {got:?}"
        );
    }

    #[test]
    fn disconnected_outgoing_timeout() {
        let mut data = Data::new(Addr::new("M0THC-1"));
        let con = Disconnected::new();

        // First attempt.
        dbg!("First attempt");
        let (con, events) = handle(&con, &mut data, &Event::Connect(Addr::new("M0THC-2")));
        let con = con.unwrap();
        assert_eq!(con.name(), "AwaitingConnection");
        assert_eq!(data.peer, Some(Addr::new("M0THC-2")));
        assert_all(
            &[ReturnEvent::Packet(Packet {
                src: Addr::new("M0THC-1"),
                dst: Addr::new("M0THC-2"),
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
                assert_eq!(data.peer, Some(Addr::new("M0THC-2")));
                assert_all(
                    &[ReturnEvent::Packet(Packet {
                        src: Addr::new("M0THC-1"),
                        dst: Addr::new("M0THC-2"),
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
    }

    #[test]
    fn disconnected_incoming() {
        let mut data = Data::new(Addr::new("M0THC-1"));
        let con = Disconnected::new();

        let (con, events) = handle(
            &con,
            &mut data,
            &Event::Sabm(Sabm { poll: true }, Addr::new("M0THC-2")),
        );
        let con = con.unwrap();
        assert_eq!(con.name(), "Connected");
        assert_eq!(data.peer, Some(Addr::new("M0THC-2")));
        assert_all(
            &[ReturnEvent::Packet(Packet {
                src: Addr::new("M0THC-1"),
                dst: Addr::new("M0THC-2"),
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
    }

    #[test]
    fn connected() {
        let mut data = Data::new(Addr::new("M0THC-1"));
        data.peer = Some(Addr::new("M0THC-2"));
        let con = Connected::new();

        // Receive info.
        let (c2, events) = handle(
            &con,
            &mut data,
            &Event::Iframe(
                Iframe {
                    payload: vec![1, 2, 3],
                },
                true,
            ),
        );
        assert!(matches![c2, None]);
        assert_all(
            &[ReturnEvent::Data(Res::Some(vec![1, 2, 3]))],
            &events,
            "iframe",
        );
    }

    #[test]
    fn disconnect() {
        let mut data = Data::new(Addr::new("M0THC-1"));
        data.peer = Some(Addr::new("M0THC-2"));
        let con = Connected::new();
        let (c2, events) = handle(&con, &mut data, &Event::Disc(Disc { poll: true }));
        assert_eq!(c2.unwrap().name(), "Disconnected");
        assert_all(
            &[
                ReturnEvent::Data(Res::EOF),
                ReturnEvent::Packet(Packet {
                    src: Addr::new("M0THC-1"),
                    dst: Addr::new("M0THC-2"),
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
    }
}
