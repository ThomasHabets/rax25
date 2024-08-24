use crate::{Addr, Disc, Dm, Iframe, Packet, PacketType, Sabm, Sabme, Ua, Ui};

#[derive(Debug, PartialEq)]
pub enum Event {
    Connect(Addr),
    Sabm(Sabm, Addr),
    Sabme(Sabme, Addr),
    Dm(Dm),
    Ui(Ui, bool),
    Disc(Disc),
    Iframe(Iframe, bool),
    Ua(Ua),
}

#[derive(Debug, PartialEq)]
pub enum ReturnEvent {
    Packet(Packet),
    DlError(DlError),
    Data(Res),
}

impl ReturnEvent {
    pub fn serialize(&self) -> Option<Vec<u8>> {
        Some(match self {
            ReturnEvent::Packet(p) => p.serialize(),
            _ => todo!(),
        })
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

const DEFAULT_SRT: u32 = 3000;

#[derive(Debug, Default)]
pub struct Timer {}
impl Timer {
    fn start(&mut self) {}
    fn stop(&mut self) {}
    fn restart(&mut self) {}
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
    srt: u32, // TODO: double?
    t1v: u32,
    n1: u32,
    n2: u32,
    rc: u32,
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
            srt: 0,
            t1v: 0,
            n2: 0,
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
        self.t1.restart();
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
    fn connect(&self, _data: &mut Data, _addr: &Addr) -> Vec<Action> {
        dbg!("TODO: unexpected DLConnect");
        vec![]
    }
    fn sabm(&self, data: &mut Data, src: &Addr, packet: &Sabm) -> Vec<Action>;
    fn sabme(&self, data: &mut Data, src: &Addr, packet: &Sabme) -> Vec<Action>;
    fn iframe(&self, _data: &mut Data, _packet: &Iframe, _cr: bool) -> Vec<Action> {
        dbg!("TODO; unexpected iframe");
        vec![]
    }
    fn ui(&self, _data: &mut Data, _cr: bool, _packet: &Ui) -> Vec<Action> {
        vec![]
    }
    fn ua(&self, _data: &mut Data, _packet: &Ua) -> Vec<Action> {
        dbg!("TODO; unexpected UA");
        vec![]
    }
    fn dm(&self, data: &mut Data, packet: &Dm) -> Vec<Action>;
    fn disc(&self, data: &mut Data, packet: &Disc) -> Vec<Action>;
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
        data.srt = DEFAULT_SRT;
        data.t1v = 2 * data.srt;
        data.t3.start();
        data.peer = Some(src);
        vec![
            Action::SendUa(poll),
            Action::State(Box::new(Connected::new())),
        ]
    }
}

impl State for Disconnected {
    // Page 85.
    fn connect(&self, data: &mut Data, addr: &Addr) -> Vec<Action> {
        // It says "SAT" in the PDF, but surely means SRT?
        data.peer = Some(addr.clone());
        data.srt = DEFAULT_SRT;
        data.t1v = 2 * data.srt;
        data.layer3_initiated = true;
        vec![
            // Action::State(Box::new(AwaitingConnection::new())),
            data.establish_data_link(),
        ]
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

    fn dm(&self, _data: &mut Data, _packet: &Dm) -> Vec<Action> {
        vec![]
    }
    // Page 84.
    fn disc(&self, _data: &mut Data, packet: &Disc) -> Vec<Action> {
        vec![Action::SendDm(packet.poll)]
    }
}

struct Connected {}

impl Connected {
    fn new() -> Self {
        Self {}
    }
}
impl State for Connected {
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
                // TODO: Action::State(Box::new(AwaitingConnection::new())),
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
        Event::Sabm(p, src) => state.sabm(data, src, p),
        Event::Sabme(p, src) => state.sabme(data, src, p),
        Event::Dm(dm) => state.dm(data, dm),
        Event::Ui(p, cr) => state.ui(data, *cr, p),
        Event::Disc(p) => state.disc(data, p),
        Event::Iframe(p, command_response) => state.iframe(data, p, *command_response),
        Event::Ua(p) => state.ua(data, p),
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
    fn server() {
        let mut data = Data::new(Addr::new("M0THC-1"));
        let con = new();

        // Connect.
        let (con, events) = handle(
            &*con,
            &mut data,
            &Event::Sabm(Sabm { poll: true }, Addr::new("M0THC-2")),
        );
        let con = con.unwrap();
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

        // Receive info.
        let (c2, events) = handle(
            &*con,
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

        // Disconnect.
        let (_con, events) = handle(&*con, &mut data, &Event::Disc(Disc { poll: true }));
        //let con = con.unwrap();
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
