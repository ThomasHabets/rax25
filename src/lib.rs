use anyhow::{Error, Result};
use log::{debug, error};
use std::io::{Read, Write};

mod fcs;
pub mod state;

const USE_FCS: bool = false;

/// Source or dst addr.
#[derive(Debug, Clone, PartialEq)]
pub struct Addr {
    t: String,
    rbit_ext: bool,
    highbit: bool,
    lowbit: bool,
    rbit_dama: bool,
}

impl Addr {
    pub fn new(s: &str) -> Result<Self> {
        let s = s.to_uppercase();
        let re = regex::Regex::new(r"^[A-Z0-9]{3,6}(?:-(?:[0-9]|1[0-5]))?$")
            .expect("can't happen: Regex compile fail");
        if !re.is_match(&s) {
            return Err(Error::msg(format!("invalid callsign: {s}")));
        }
        Ok(Self {
            t: s,
            rbit_ext: false,
            highbit: false,
            lowbit: false,
            rbit_dama: false,
        })
    }
    pub fn new_bits(
        s: &str,
        lowbit: bool,
        highbit: bool,
        rbit_ext: bool,
        rbit_dama: bool,
    ) -> Result<Self> {
        let mut a = Self::new(s)?;
        a.lowbit = lowbit;
        a.highbit = highbit;
        a.rbit_ext = rbit_ext;
        a.rbit_dama = rbit_dama;
        Ok(a)
    }

    #[must_use]
    pub fn call(&self) -> &str {
        &self.t
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 7 {
            return Err(Error::msg(format!(
                "invalid serialized callsign: {bytes:?}"
            )));
        }
        let call = {
            let call = bytes
                .iter()
                .take(6)
                .map(|&c| (c >> 1) as char)
                .collect::<String>()
                .trim_end()
                .to_string();
            let ssid = (bytes[6] >> 1) & 15;
            if ssid > 0 {
                call + "-" + &ssid.to_string()
            } else {
                call
            }
        };
        Self::new_bits(
            &call,
            bytes[6] & 1 != 0,
            bytes[6] & 0x80 != 0,
            bytes[6] & 0b0100_0000 == 0,
            bytes[6] & 0b0010_0000 == 0,
        )
    }

    #[must_use]
    pub fn serialize(
        &self,
        lowbit: bool,
        highbit: bool,
        rbit_ext: bool,
        rbit_dama: bool,
    ) -> Vec<u8> {
        // TODO: confirm format.
        let mut ret = vec![b' ' << 1; 7];
        for (i, ch) in self.t.chars().take(6).enumerate() {
            if ch == '-' {
                break;
            }
            ret[i] = (ch as u8) << 1;
        }
        let ssid = {
            let s: Vec<_> = self.t.split('-').collect();
            if s.len() == 1 {
                0
            } else {
                s[1].parse::<u8>().unwrap()
            }
        };
        ret[6] = (ssid << 1)
            | (if rbit_ext { 0 } else { 0b0100_0000 })
            | (if rbit_dama { 0 } else { 0b0010_0000 })
            | (if lowbit { 1 } else { 0 })
            | (if highbit { 0x80 } else { 0 });
        ret
    }
    //fn as_str(&self) -> &str {&self.t }
}

#[derive(Debug, PartialEq)]
pub struct Packet {
    src: Addr,
    dst: Addr,
    digipeater: Vec<Addr>,
    rr_extseq: bool,
    command_response: bool,
    command_response_la: bool,
    rr_dist1: bool,
    packet_type: PacketType,
}

#[derive(Debug, PartialEq)]
pub enum PacketType {
    Sabm(Sabm),
    Ua(Ua),
    Dm(Dm),
    Disc(Disc),
    Iframe(Iframe),
    Rr(Rr),
    Rnr(Rnr),
    Rej(Rej),
    Srej(Srej),
    Frmr(Frmr),
    Xid(Xid),
    Ui(Ui),
    Test(Test),
}

/// SABM - Set Ansynchronous Balanced Mode (4.3.3.1)
///
///
#[derive(Clone, Debug, PartialEq)]
pub struct Sabm {
    poll: bool,
}

// Unnumbered frames. Ending in 11.
#[allow(clippy::unusual_byte_groupings)]
pub const CONTROL_SABM: u8 = 0b001_0_11_11;
#[allow(clippy::unusual_byte_groupings)]
pub const CONTROL_SABME: u8 = 0b011_0_11_11;
#[allow(clippy::unusual_byte_groupings)]
pub const CONTROL_UI: u8 = 0b000_0_00_11;
#[allow(clippy::unusual_byte_groupings)]
pub const CONTROL_DISC: u8 = 0b010_0_00_11;
#[allow(clippy::unusual_byte_groupings)]
pub const CONTROL_DM: u8 = 0b0000_1111;
pub const CONTROL_UA: u8 = 0b0110_0011;
pub const CONTROL_TEST: u8 = 0b1110_0011;
pub const CONTROL_XID: u8 = 0b1010_1111;
pub const CONTROL_FRMR: u8 = 0b1000_0111;

// Supervisor frames. Ending in 01.
pub const CONTROL_RR: u8 = 0b0000_0001;
pub const CONTROL_RNR: u8 = 0b0000_0101;
pub const CONTROL_REJ: u8 = 0b0000_1001;
pub const CONTROL_SREJ: u8 = 0b0000_1101;

// Iframes end in 0.
pub const CONTROL_IFRAME: u8 = 0b0000_0000;

// Masks.
pub const CONTROL_POLL: u8 = 0b0001_0000;
pub const NR_MASK: u8 = 0b1110_0000;
pub const TYPE_MASK: u8 = 0b0000_0011;
pub const NO_L3: u8 = 0xF0;

impl Packet {
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut ret = Vec::with_capacity(
            14 + 1
                + if let PacketType::Iframe(s) = &self.packet_type {
                    s.payload.len() + 1
                } else {
                    0
                },
        );
        ret.extend(
            self.dst
                .serialize(false, self.command_response, self.rr_dist1, false),
        );
        assert_ne!(self.command_response, self.command_response_la);
        ret.extend(self.src.serialize(
            self.digipeater.is_empty(),
            self.command_response_la,
            self.rr_extseq,
            false,
        ));
        match &self.packet_type {
            PacketType::Sabm(s) => ret.push(CONTROL_SABM | if s.poll { CONTROL_POLL } else { 0 }),
            PacketType::Ua(s) => ret.push(CONTROL_UA | if s.poll { CONTROL_POLL } else { 0 }),
            PacketType::Rej(s) => ret.push(CONTROL_REJ | if s.poll { CONTROL_POLL } else { 0 }),
            PacketType::Srej(s) => ret.push(CONTROL_SREJ | if s.poll { CONTROL_POLL } else { 0 }),
            PacketType::Test(s) => {
                ret.push(CONTROL_TEST | if s.poll { CONTROL_POLL } else { 0 });
                ret.extend(&s.payload);
            }
            // TODO: XID data too.
            PacketType::Xid(s) => ret.push(CONTROL_XID | if s.poll { CONTROL_POLL } else { 0 }),
            // TODO: UI data too.
            PacketType::Ui(s) => ret.push(CONTROL_UI | if s.push { CONTROL_POLL } else { 0 }),
            // TODO: FRMR data too.
            PacketType::Frmr(s) => ret.push(CONTROL_FRMR | if s.poll { CONTROL_POLL } else { 0 }),
            PacketType::Dm(s) => ret.push(CONTROL_DM | if s.poll { CONTROL_POLL } else { 0 }),
            PacketType::Rr(s) => ret
                .push(CONTROL_RR | if s.poll { CONTROL_POLL } else { 0 } | ((s.nr << 5) & NR_MASK)),
            PacketType::Rnr(s) => ret.push(
                CONTROL_RNR | if s.poll { CONTROL_POLL } else { 0 } | ((s.nr << 5) & NR_MASK),
            ),
            PacketType::Iframe(iframe) => {
                ret.push(
                    CONTROL_IFRAME
                        | if iframe.poll { CONTROL_POLL } else { 0 }
                        | ((iframe.nr << 5) & 0b1110_0000)
                        | ((iframe.ns << 1) & 0b0000_1110),
                );
                ret.push(iframe.pid);
                ret.extend(&iframe.payload);
            }
            PacketType::Disc(disc) => {
                ret.push(CONTROL_DISC | if disc.poll { CONTROL_POLL } else { 0 })
            }
        };
        if USE_FCS {
            let crc = fcs::fcs(&ret);
            ret.push(crc[0]);
            ret.push(crc[1]);
        }
        ret
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let do_fcs = USE_FCS;
        if bytes.len() < if do_fcs { 17 } else { 15 } {
            return Err(Error::msg(format!(
                "packet too short: {} bytes",
                bytes.len()
            )));
        }
        // TODO: check FCS.
        let bytes = if do_fcs {
            &bytes[..(bytes.len() - 2)]
        } else {
            bytes
        };
        let dst = Addr::parse(&bytes[0..7])?;
        let src = Addr::parse(&bytes[7..14])?;

        // TODO: parse digipeater.
        let control = bytes[14];
        let poll = control & CONTROL_POLL != 0;
        let nr = (control >> 5) & 7; // Used for iframe and supervisory.
        let ns = (control >> 1) & 7; // Used for iframe only.
        Ok(Packet {
            src: src.clone(),
            dst: dst.clone(),
            command_response: dst.highbit,
            command_response_la: src.highbit,
            rr_dist1: dst.rbit_ext,
            rr_extseq: src.rbit_ext,
            digipeater: vec![],
            packet_type: match control & TYPE_MASK {
                0 | 2 => PacketType::Iframe(Iframe {
                    ns,
                    nr,
                    poll,
                    pid: NO_L3,
                    payload: bytes[16..].to_vec(),
                }),
                1 => match control & !NR_MASK & !CONTROL_POLL {
                    CONTROL_RR => PacketType::Rr(Rr { nr, poll }),
                    CONTROL_RNR => PacketType::Rnr(Rnr { nr, poll }),
                    CONTROL_REJ => PacketType::Rej(Rej { nr, poll }),
                    CONTROL_SREJ => PacketType::Srej(Srej { nr, poll }),
                    _ => panic!("Impossible logic error: {control} failed to be supervisor"),
                },
                3 => match !CONTROL_POLL & bytes[14] {
                    CONTROL_SABME => PacketType::Sabm(Sabm { poll }),
                    CONTROL_SABM => PacketType::Sabm(Sabm { poll }),
                    CONTROL_UA => PacketType::Ua(Ua { poll }),
                    CONTROL_DISC => PacketType::Disc(Disc { poll }),
                    CONTROL_DM => PacketType::Dm(Dm { poll }),
                    CONTROL_FRMR => PacketType::Frmr(Frmr { poll }),
                    CONTROL_UI => PacketType::Ui(Ui { push: poll }),
                    CONTROL_XID => PacketType::Xid(Xid { poll }),
                    CONTROL_TEST => PacketType::Test(Test {
                        poll,
                        payload: bytes[15..].to_vec(),
                    }),
                    c => todo!("Control {c:b} not implemented"),
                },
                _ => panic!("Logic error: {control} & 3 > 3"),
            },
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct Sabme {
    poll: bool,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Rr {
    poll: bool,
    nr: u8,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Rej {
    poll: bool,
    nr: u8,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Srej {
    poll: bool,
    nr: u8,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Frmr {
    poll: bool,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Test {
    poll: bool,
    payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Xid {
    poll: bool,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Rnr {
    poll: bool,
    nr: u8,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Ua {
    poll: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Iframe {
    nr: u8,
    ns: u8,
    poll: bool,
    pid: u8,
    payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Ui {
    push: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Dm {
    poll: bool,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Disc {
    poll: bool,
}

pub trait Kisser {
    fn send(&mut self, frame: &[u8]) -> Result<()>;
    fn recv_timeout(&mut self, timeout: std::time::Duration) -> Result<Option<Vec<u8>>>;
}

#[cfg(test)]
#[derive(Default, Debug)]
struct FakeKiss {
    queue: std::collections::VecDeque<Vec<u8>>,
}

#[cfg(test)]
impl FakeKiss {
    #[must_use]
    fn make_iframe(src: Addr, dst: Addr, payload: Vec<u8>) -> Packet {
        Packet {
            src,
            dst,
            command_response: true,
            command_response_la: false,
            rr_dist1: false,
            rr_extseq: false,
            digipeater: vec![],
            packet_type: PacketType::Iframe(Iframe {
                nr: 0,
                pid: 0xF0,
                ns: 0,
                poll: true, // TODO: poll or no?
                payload,
            }),
        }
    }

    #[must_use]
    fn make_ua(src: Addr, dst: Addr) -> Packet {
        Packet {
            src,
            dst,
            command_response: true,
            command_response_la: false,
            rr_dist1: false,
            rr_extseq: false,
            digipeater: vec![],
            packet_type: PacketType::Ua(Ua { poll: true }),
        }
    }
}

#[cfg(test)]
impl Kisser for FakeKiss {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        let packet = Packet::parse(frame)?;
        match &packet.packet_type {
            PacketType::Sabm(_) => {
                self.queue
                    .push_back(Self::make_ua(packet.dst.clone(), packet.src.clone()).serialize());
            }
            PacketType::Iframe(_) => {
                self.queue.push_back(
                    Self::make_iframe(packet.dst.clone(), packet.src.clone(), vec![3, 2, 1])
                        .serialize(),
                );
            }
            PacketType::Disc(_) => {
                self.queue
                    .push_back(Self::make_ua(packet.dst.clone(), packet.src.clone()).serialize());
            }
            _ => todo!(),
        }
        Ok(())
    }
    fn recv_timeout(&mut self, _timeout: std::time::Duration) -> Result<Option<Vec<u8>>> {
        Ok(self.queue.pop_front())
    }
}

pub struct Kiss {
    buf: std::collections::VecDeque<u8>,
    port: Box<dyn serialport::SerialPort>,
}

impl Kiss {
    pub fn new(port: &str) -> Result<Self> {
        //            let mut stream = std::net::TcpStream::connect("127.0.0.1:8001")?;
        let port = serialport::new(port, 9600)
            .flow_control(serialport::FlowControl::None)
            .parity(serialport::Parity::None)
            .data_bits(serialport::DataBits::Eight)
            .stop_bits(serialport::StopBits::One)
            .open()?;
        port.clear(serialport::ClearBuffer::All)?;
        Ok(Self {
            buf: std::collections::VecDeque::new(),
            port,
            //        port: Box::new(stream),
        })
    }
}

const KISS_FEND: u8 = 0xC0;
const KISS_FESC: u8 = 0xDB;
const KISS_TFEND: u8 = 0xDC;
const KISS_TFESC: u8 = 0xDD;

#[must_use]
fn escape(bytes: &[u8]) -> Vec<u8> {
    let mut ret = Vec::new();
    ret.push(KISS_FEND);
    ret.push(0); // TODO: port
    for b in bytes {
        match *b {
            KISS_FEND => ret.extend(vec![KISS_FESC, KISS_TFEND]),
            KISS_FESC => ret.extend(vec![KISS_FESC, KISS_TFESC]),
            b => ret.push(b),
        }
    }
    ret.push(KISS_FEND);
    ret
}

#[must_use]
fn find_frame(vec: &std::collections::VecDeque<u8>) -> Option<(usize, usize)> {
    let mut start_index = None;

    for (i, &value) in vec.iter().enumerate() {
        if value == 0xC0 {
            if let Some(start) = start_index {
                // If start_index is already set and we find another 0xC0
                return Some((start, i));
            } else {
                // Set the start_index when we find the first 0xC0
                start_index = Some(i);
            }
        }
    }

    None // Return None if no valid subrange is found
}

#[must_use]
fn unescape(data: &[u8]) -> Vec<u8> {
    let mut unescaped = Vec::with_capacity(data.len());
    let mut is_escaped = false;

    for &byte in data {
        if is_escaped {
            // XOR the byte with 0x20 to revert the escaping
            unescaped.push(byte ^ 0x20);
            is_escaped = false;
        } else if byte == KISS_FESC {
            // Next byte is escaped, so set the flag
            is_escaped = true;
        } else {
            // Normal byte, just push it to the output
            unescaped.push(byte);
        }
    }
    unescaped
}

// For now this is a KISS interface. But it needs to be changed to allow multiplexing.
impl Kisser for Kiss {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        debug!("Sending frame… {frame:?}");
        self.port.write_all(&escape(frame))?;
        self.port.flush()?;
        Ok(())
    }
    fn recv_timeout(&mut self, timeout: std::time::Duration) -> Result<Option<Vec<u8>>> {
        let end = std::time::Instant::now() + timeout;
        loop {
            self.port.set_timeout(end - std::time::Instant::now())?;
            let mut buf = [0u8; 1];
            let buf = match self.port.read(&mut buf) {
                Ok(n) => &buf[..n],
                Err(e) => {
                    debug!("TODO: Read error: {e}, assuming timeout");
                    break;
                }
            };
            debug!("Got {} bytes from serial", buf.len());
            self.buf.extend(buf);
            while let Some((a, b)) = find_frame(&self.buf) {
                if b - a < 14 {
                    debug!("short packet {a} {b}");
                    self.buf.drain(..(a + 1));
                    continue;
                }
                let bytes: Vec<_> = self
                    .buf
                    .iter()
                    .skip(a + 2)
                    .take(b - a - 2)
                    .cloned()
                    .collect();
                self.buf.drain(..b);
                debug!("After drain: {:?}", self.buf);
                let bytes = unescape(&bytes);
                if bytes.len() > 14 {
                    debug!("Found from (not yet unescaped) from {a} to {b}: {bytes:?}");
                    let _packet = Packet::parse(&bytes)?;
                    // dbg!(packet);
                    return Ok(Some(bytes.to_vec()));
                }
            }
        }
        Ok(None)
    }
}

pub struct Client {
    kiss: Box<dyn Kisser>,
    pub(crate) data: state::Data,
    state: Box<dyn state::State>,

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
    #[must_use]
    pub fn new(me: Addr, kiss: Box<dyn Kisser>) -> Self {
        Self {
            kiss,
            data: state::Data::new(me),
            state: state::new(),
            incoming: std::collections::VecDeque::new(),
        }
    }
    pub fn connect(&mut self, addr: &Addr) -> Result<()> {
        self.actions(state::Event::Connect(addr.clone()));
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
                    if self.state.name() == "Connected" {
                        debug!("YAY! CONNECTED!");
                        // TODO: don't compare strings.
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
            // TODO: stop using string comparison.
            if self.state.name() == "Disconnected" {
                debug!("connection timeout");
                return Err(Error::msg("connection timeout"));
            }
        }
    }
    pub fn disconnect(&mut self) -> Result<()> {
        self.actions(state::Event::Disconnect);
        Ok(())
    }
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        self.actions(state::Event::Data(data.to_vec()));
        Ok(())
    }
    pub fn try_read(&mut self) -> Result<Option<Packet>> {
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
    pub fn read_until(
        &mut self,
        done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<Option<Vec<u8>>> {
        while self.incoming.is_empty() {
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
    pub fn actions_packet(&mut self, packet: &Packet) -> Result<()> {
        match &packet.packet_type {
            PacketType::Ua(ua) => self.actions(state::Event::Ua(ua.clone())),
            PacketType::Sabm(p) => self.actions(state::Event::Sabm(p.clone(), packet.src.clone())),
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

    pub fn actions(&mut self, event: state::Event) {
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
                    state::Res::EOF => eprintln!("EOF!!!!"),
                    state::Res::Some(d) => {
                        debug!("DATA DELIVERED>>> {:?}", String::from_utf8(d.clone()));
                        self.incoming.extend(d);
                    }
                },
                _ => {}
            }

            if let Some(frame) = act.serialize() {
                self.kiss.send(&frame).unwrap();
            }
        }
        // TODO: check timers.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client() -> Result<()> {
        let k = FakeKiss::default();
        let mut c = Client::new(Addr::new("M0THC-1")?, Box::new(k));
        c.data.srt_default = std::time::Duration::from_millis(1);
        c.connect(&Addr::new("M0THC-2")?)?;
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
    fn addr_serial() -> Result<()> {
        // TODO: test invalid calls.
        let a = Addr::new("M0THC")?.serialize(true, false, false, false);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 97]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC");

        let a = Addr::new("M0THC-0")?.serialize(true, false, false, false);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 97]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC");

        let a = Addr::new("M0THC-1")?.serialize(true, false, false, false);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 99]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC-1");

        let a = Addr::new("M0THC-2")?.serialize(false, true, false, false);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 100 + 0x80]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC-2");

        let a = Addr::new("M0THC-3")?.serialize(false, false, true, false);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 38]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC-3");

        let a = Addr::new("M0THC-4")?.serialize(false, false, false, true);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 72]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC-4");
        Ok(())
    }

    #[test]
    fn serialize_sabm() -> Result<()> {
        let src = Addr::new("M0THC-1")?;
        let dst = Addr::new("M0THC-2")?;
        assert_eq!(
            Packet {
                src: src.clone(),
                dst: dst.clone(),
                command_response: true,
                command_response_la: false,
                rr_dist1: false,
                rr_extseq: false,
                digipeater: vec![],
                packet_type: PacketType::Sabm(Sabm { poll: true })
            }
            .serialize(),
            vec![154, 96, 168, 144, 134, 64, 228, 154, 96, 168, 144, 134, 64, 99, 63], //, 111, 212]
        );
        assert_eq!(
            Packet {
                command_response: true,
                command_response_la: false,
                digipeater: vec![],
                rr_dist1: false,
                rr_extseq: false,
                src,
                dst,
                packet_type: PacketType::Sabm(Sabm { poll: false })
            }
            .serialize(),
            vec![154, 96, 168, 144, 134, 64, 228, 154, 96, 168, 144, 134, 64, 99, 47], // , 238, 196]
        );
        Ok(())
    }
}
