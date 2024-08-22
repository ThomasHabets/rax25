/// Source or dst addr.
#[derive(Debug, Clone, PartialEq)]
pub struct Addr {
    t: String,
}

impl Addr {
    fn new(s: &str) -> Self {
        Self { t: s.to_string() }
    }
    //fn as_str(&self) -> &str {&self.t }
}

#[derive(Debug, PartialEq)]
pub struct Sabm {
    src: Addr,
    dst: Addr,
    poll: bool,
}

#[derive(Debug, PartialEq)]
pub struct Sabme {
    src: Addr,
    dst: Addr,
    poll: bool,
}

#[derive(Debug, PartialEq)]
pub struct Ua {
    src: Addr,
    dst: Addr,
    poll: bool,
}

#[derive(Debug, PartialEq)]
pub struct Iframe {
    src: Addr,
    dst: Addr,
    payload: Vec<u8>,
    command_response: bool,
}

#[derive(Debug, PartialEq)]
pub struct Ui {
    src: Addr,
    dst: Addr,
    push: bool,
    command_response: bool,
}

#[derive(Debug, PartialEq)]
pub struct Dm {
    src: Addr,
    dst: Addr,
}
#[derive(Debug, PartialEq)]
pub struct Disc {
    src: Addr,
    dst: Addr,
    poll: bool,
}

#[derive(Debug, PartialEq)]
pub enum Event {
    Sabm(Sabm),
    Sabme(Sabme),
    Dm(Dm),
    Ui(Ui),
    Disc(Disc),
    Iframe(Iframe),
    Ua(Ua),
}

#[derive(Debug, PartialEq)]
pub enum ReturnEvent {
    Sabm(Sabm),
    Sabme(Sabme),
    Dm(Dm),
    Ui(Ui),
    Disc(Disc),
    Iframe(Iframe),
    Ua(Ua),
    Data(Res),
}

#[derive(Debug)]
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

impl Event {
    fn addrs(&self) -> (&Addr, &Addr) {
        match self {
            Event::Sabm(sabm) => (&sabm.src, &sabm.dst),
            Event::Sabme(p) => (&p.src, &p.dst),
            Event::Dm(dm) => (&dm.src, &dm.dst),
            Event::Ui(p) => (&p.src, &p.dst),
            Event::Disc(p) => (&p.src, &p.dst),
            Event::Iframe(p) => (&p.src, &p.dst),
            Event::Ua(p) => (&p.src, &p.dst),
        }
    }
}

const DEFAULT_SRT: u32 = 3000;

#[derive(Debug, Default)]
pub struct Timer {}
impl Timer {
    fn start(&mut self) {}
    fn stop(&mut self) {}
    fn restart(&mut self) {}
}

#[derive(Debug, Default)]
pub struct Data {
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
    #[cfg(test)]
    fn new() -> Self {
        Self {
            n1: 65000, // Max number of octets in the information field of a frame.
            ..Default::default()
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
    fn for_me(&self, src: &Addr, dst: &Addr) -> bool;

    fn sabm(&self, data: &mut Data, packet: &Sabm) -> Vec<Action>;
    fn sabme(&self, data: &mut Data, packet: &Sabme) -> Vec<Action>;
    fn iframe(&self, _data: &mut Data, _packet: &Iframe) -> Vec<Action> {
        dbg!("TODO; unexpected iframe");
        vec![]
    }
    fn ui(&self, _data: &mut Data, _packet: &Ui) -> Vec<Action> {
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
fn ui_check(command: bool) {
    if !command {
        // TODO: DlError::Q
        return;
    }
    if
    /*packet too long*/
    false {
        // TODO: DlError::K
        return;
    }
    dbg!("DL-UNIT_DATA indication");
}

/// Disconnected state.
///
/// I think this is fully implemented for AX.25 2.0. No SABME yet, though.
///
/// This is a state diagram for a connection. Any non-listening socket
/// should in theory cause `SendDm(p.poll)`, but out of scope.
struct Disconnected {
    addr: Addr,
}
impl Disconnected {
    pub fn new(addr: Addr) -> Self {
        Self { addr }
    }

    // Page 85.
    fn sabm_and_sabme(&self, data: &mut Data, src: Addr, dst: Addr, poll: bool) -> Vec<Action> {
        data.clear_exception_conditions();
        data.vs = 0;
        data.va = 0;
        data.vr = 0;
        data.srt = DEFAULT_SRT;
        data.t1v = 2 * data.srt;
        data.t3.start();
        vec![
            Action::SendUa(poll),
            Action::State(Box::new(Connected::new(src, dst))),
        ]
    }
}

impl State for Disconnected {
    fn for_me(&self, _src: &Addr, dst: &Addr) -> bool {
        self.addr == *dst
    }

    // Page 84.
    fn ui(&self, _data: &mut Data, packet: &Ui) -> Vec<Action> {
        ui_check(packet.command_response);
        if packet.push {
            vec![Action::SendDm(true)]
        } else {
            vec![]
        }
    }

    // Page 85.
    fn sabm(&self, data: &mut Data, packet: &Sabm) -> Vec<Action> {
	data.set_version_2();
	self.sabm_and_sabme(data, packet.src.clone(), packet.dst.clone(), packet.poll)
    }
    // Page 85.
    fn sabme(&self, data: &mut Data, packet: &Sabme) -> Vec<Action> {
	data.set_version_2_2();
	self.sabm_and_sabme(data, packet.src.clone(), packet.dst.clone(), packet.poll)
    }

    fn dm(&self, _data: &mut Data, _packet: &Dm) -> Vec<Action> {
        vec![]
    }
    // Page 84.
    fn disc(&self, _data: &mut Data, packet: &Disc) -> Vec<Action> {
        vec![Action::SendDm(packet.poll)]
    }
}

struct Connected {
    peer: Addr,
    me: Addr,
}

impl Connected {
    fn new(peer: Addr, me: Addr) -> Self {
        Self { peer, me }
    }
}
impl State for Connected {
    fn for_me(&self, src: &Addr, dst: &Addr) -> bool {
        self.me == *dst && *src == self.peer
    }

    // Page 93.
    fn sabm(&self, _data: &mut Data, _packet: &Sabm) -> Vec<Action> {
        dbg!("TODO: Connected: sabm not handled");
        vec![]
    }
    // Page 93.
    fn sabme(&self, _data: &mut Data, _packet: &Sabme) -> Vec<Action> {
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
            Action::State(Box::new(Disconnected::new(self.me.clone()))),
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
            Action::State(Box::new(Disconnected::new(self.me.clone()))),
	]
    }
    
    // Page 96 & 102.
    fn iframe(&self, d: &mut Data, p: &Iframe) -> Vec<Action> {
        if !p.command_response {
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
    Box::new(Disconnected::new(Addr::new("M0THC-1"))) // TODO
}

#[derive(Debug, PartialEq)]
pub enum Res {
    None,
    EOF,
    Some(Vec<u8>),
}

pub fn handle(
    state: Box<dyn State>,
    data: &mut Data,
    packet: &Event,
) -> (Box<dyn State>, Vec<ReturnEvent>) {
    let (src, dst) = packet.addrs();
    if !state.for_me(src, dst) {
        return (state, vec![]);
    }
    let actions = match packet {
        Event::Sabm(sabm) => state.sabm(data, sabm),
        Event::Sabme(p) => state.sabme(data, p),
        Event::Dm(dm) => state.dm(data, dm),
        Event::Ui(p) => state.ui(data, p),
        Event::Disc(p) => state.disc(data, p),
        Event::Iframe(p) => state.iframe(data, p),
        Event::Ua(p) => state.ua(data, p),
    };
    let mut ret = Vec::new();

    // Save non-state actions.
    for act in &actions {
        use Action::*;
        match act {
            Action::State(_) => {} // Ignore state change at this stage.
            DlError(code) => {
                dbg!("Dlerror: {:?}", code);
            }
            SendUa(poll) => ret.push(ReturnEvent::Ua(Ua {
                src: dst.clone(),
                dst: src.clone(),
                poll: *poll,
            })),
            SendDm(_) => {} // TODO
	    SendSabm(poll) => ret.push(ReturnEvent::Sabm(Sabm {
                src: dst.clone(),
                dst: src.clone(),
                poll: *poll,
	    })),

            // TODO: can we avoid the copy?
            Deliver(p) => ret.push(ReturnEvent::Data(Res::Some(p.to_vec()))),
            EOF => ret.push(ReturnEvent::Data(Res::EOF)),
        }
    }
    for act in actions {
        // Non-statechange actions handled above.
        if let Action::State(new_state) = act {
            return (new_state, ret);
        }
    }
    (state, ret)
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
        let mut data = Data::new();
        let con = new();

        // Connect.
        let (con, events) = handle(
            con,
            &mut data,
            &Event::Sabm(Sabm {
                src: Addr::new("M0THC-2"),
                dst: Addr::new("M0THC-1"),
                poll: true,
            }),
        );
        assert_all(
            &[ReturnEvent::Ua(Ua {
                src: Addr::new("M0THC-1"),
                dst: Addr::new("M0THC-2"),
                poll: true,
            })],
            &events,
            "connect",
        );

        // Receive info.
        let (con, events) = handle(
            con,
            &mut data,
            &Event::Iframe(Iframe {
                src: Addr::new("M0THC-2"),
                dst: Addr::new("M0THC-1"),
                payload: vec![1, 2, 3],
                command_response: true,
            }),
        );
        assert_all(
            &[ReturnEvent::Data(Res::Some(vec![1, 2, 3]))],
            &events,
            "iframe",
        );

        // Disconnect.
        let (_con, events) = handle(
            con,
            &mut data,
            &Event::Disc(Disc {
                src: Addr::new("M0THC-2"),
                dst: Addr::new("M0THC-1"),
                poll: true,
            }),
        );
        assert_all(&[
	    ReturnEvent::Data(Res::EOF),
	    ReturnEvent::Ua(Ua{
                src: Addr::new("M0THC-1"),
                dst: Addr::new("M0THC-2"),
		poll: true,
	    }),
	], &events, "disconnect");
    }
}
