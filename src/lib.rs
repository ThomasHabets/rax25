use anyhow::{Error, Result};
use log::debug;
use std::io::{Read, Write};

mod fcs;
pub mod state;

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
    pub fn new(s: &str) -> Self {
        // TODO: check format
        Self {
            t: s.to_string(),
            rbit_ext: false,
            highbit: false,
            lowbit: false,
            rbit_dama: false,
        }
    }
    pub fn new_bits(s: &str, lowbit: bool, highbit: bool, rbit_ext: bool, rbit_dama: bool) -> Self {
        Self {
            t: s.to_string(),
            lowbit,
            highbit,
            rbit_ext,
            rbit_dama,
        }
    }
    pub fn display(&self) -> &str {
        &self.t
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 7 {
            return Err(Error::msg(format!(
                "invalid serialized callsign: {bytes:?}"
            )));
        }
        let mut r = String::new();
        for byte in bytes.iter().take(6) {
            let ch = (byte >> 1) as char;
            if ch == ' ' {
                break;
            }
            r.push(ch)
        }
        let ssid = (bytes[6] >> 1) & 15;
        if ssid > 0 {
            r = r + "-" + &ssid.to_string();
        }

        Ok(Self {
            t: r,
            rbit_ext: bytes[6] & 0b0100_0000 == 0,
            rbit_dama: bytes[6] & 0b0010_0000 == 0,
            lowbit: bytes[6] & 1 != 0,
            highbit: bytes[6] & 0x80 != 0,
        })
    }

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
}

/// SABM - Set Ansynchronous Balanced Mode (4.3.3.1)
///
///
#[derive(Debug, PartialEq)]
pub struct Sabm {
    poll: bool,
}

#[allow(clippy::unusual_byte_groupings)]
pub const CONTROL_SABM: u8 = 0b001_0_11_11;
#[allow(clippy::unusual_byte_groupings)]
pub const CONTROL_UI: u8 = 0b000_0_00_11;
#[allow(clippy::unusual_byte_groupings)]
pub const CONTROL_SABME: u8 = 0b011_0_11_11;
#[allow(clippy::unusual_byte_groupings)]
pub const CONTROL_DISC: u8 = 0b010_0_00_11;
#[allow(clippy::unusual_byte_groupings)]
pub const CONTROL_DM: u8 = 0b000_0_11_11;
#[allow(clippy::unusual_byte_groupings)]
pub const CONTROL_UA: u8 = 0b011_0_00_11;
#[allow(clippy::unusual_byte_groupings)]
pub const CONTROL_RR: u8 = 0b000_0_00_01;
#[allow(clippy::unusual_byte_groupings)]
pub const CONTROL_REJ: u8 = 0b001_0_10_01;
#[allow(clippy::unusual_byte_groupings)]
pub const CONTROL_IFRAME: u8 = 0b000_0_00_00;
pub const CONTROL_POLL: u8 = 0b0001_0000;

impl Packet {
    pub fn serialize(&self) -> Vec<u8> {
        let mut ret = Vec::with_capacity(8 + 8 + 1); // TODO: reserve more
        ret.extend(
            self.dst
                .serialize(false, self.command_response, self.rr_dist1, false),
        );
        ret.extend(self.src.serialize(
            self.digipeater.is_empty(),
            self.command_response_la,
            self.rr_extseq,
            false,
        ));
        match &self.packet_type {
            PacketType::Sabm(s) => ret.push(CONTROL_SABM | if s.poll { CONTROL_POLL } else { 0 }),
            PacketType::Ua(s) => ret.push(CONTROL_UA | if s.poll { CONTROL_POLL } else { 0 }),
            PacketType::Iframe(iframe) => {
                ret.push(CONTROL_IFRAME | if iframe.poll { CONTROL_POLL } else { 0 });
                ret.push(iframe.pid);
                ret.extend(&iframe.payload);
            }
            _ => todo!(),
        };
        let crc = fcs::fcs(&ret);
        ret.push(crc[0]);
        ret.push(crc[1]);
        ret
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let do_fcs = false;
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
        let poll = bytes[14] & CONTROL_POLL != 0;
        Ok(Packet {
            src: src.clone(),
            dst: dst.clone(),
            command_response: dst.highbit,
            command_response_la: src.highbit,
            rr_dist1: dst.rbit_ext,
            rr_extseq: src.rbit_ext,
            digipeater: vec![],
            packet_type: if control & 1 == 0 {
                PacketType::Iframe(Iframe {
                    ns: (control >> 1) & 7,
                    nr: (control >> 5) & 7,
                    poll: ((control >> 1) & 1) == 1,
                    pid: 0xF0,
                    payload: bytes[14..].to_vec(),
                })
            } else if control & 3 == 1 {
                todo!()
            } else {
                match 0b1110_1111 & bytes[14] {
                    CONTROL_SABM => PacketType::Sabm(Sabm { poll }),
                    CONTROL_UA => PacketType::Ua(Ua { poll }),
                    c => todo!("Control {c:b} not implemented"),
                }
            },
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct Sabme {
    poll: bool,
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

#[derive(Debug, PartialEq)]
pub struct Ui {
    push: bool,
}

#[derive(Debug, PartialEq)]
pub struct Dm {
    poll: bool,
}
#[derive(Debug, PartialEq)]
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
        Ok(Self {
            buf: std::collections::VecDeque::new(),
            port: serialport::new(port, 9600).open()?,
            //        port: Box::new(stream),
        })
    }
}

const KISS_FEND: u8 = 0xC0;
const KISS_FESC: u8 = 0xDB;
const KISS_TFEND: u8 = 0xDC;
const KISS_TFESC: u8 = 0xDD;

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
        eprintln!("Sending frame… {frame:?}");
        self.port.write_all(&escape(frame))?;
        Ok(())
    }
    fn recv_timeout(&mut self, timeout: std::time::Duration) -> Result<Option<Vec<u8>>> {
        let end = std::time::Instant::now() + timeout;
        loop {
            self.port.set_timeout(end - std::time::Instant::now())?;
            let mut buf = [0u8; 1024];
            let buf = match self.port.read(&mut buf) {
                Ok(n) => &buf[..n],
                Err(e) => {
                    eprintln!("Read error: {e}, assuming timeout");
                    break;
                }
            };
            eprintln!("Got {} bytes from serial", buf.len());
            self.buf.extend(buf);
            while let Some((a, b)) = find_frame(&self.buf) {
                let bytes: Vec<_> = self
                    .buf
                    .iter()
                    .skip(a + 2)
                    .take(b - a - 2)
                    .cloned()
                    .collect();
                let bytes = unescape(&bytes);
                if bytes.len() > 14 {
                    eprintln!("Found from (not yet unescaped) from {a} to {b}: {bytes:?}");
                    let packet = Packet::parse(&bytes)?;
                    dbg!(packet);
                    return Ok(Some(bytes.to_vec()));
                }
                self.buf.drain(a..b);
            }
        }
        Ok(None)
    }
}

pub struct Client {
    kiss: Box<dyn Kisser>,
    pub(crate) data: state::Data,
    state: Box<dyn state::State>,
}

impl Client {
    pub fn new(me: Addr, kiss: Box<dyn Kisser>) -> Self {
        Self {
            kiss,
            data: state::Data::new(me),
            state: state::new(),
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
                dbg!(&packet);
                // TODO: check addresses.
                match &packet.packet_type {
                    PacketType::Ua(ua) => self.actions(state::Event::Ua(ua.clone())),
                    _ => panic!(),
                }
                if self.state.name() == "Connected" {
                    debug!("YAY! CONNECTED!");
                    // TODO: don't compare strings.
                    return Ok(());
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
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        self.actions(state::Event::Data(data.to_vec()));
        Ok(())
    }
    pub fn try_read(&mut self) -> Result<Packet> {
        Packet::parse(
            &self
                .kiss
                .recv_timeout(std::time::Duration::from_secs(1))?
                .unwrap(),
        )
    }
    pub fn actions(&mut self, event: state::Event) {
        let (state, actions) = state::handle(&*self.state, &mut self.data, &event);
        if let Some(state) = state {
            let _ = std::mem::replace(&mut self.state, state);
        }
        for act in actions {
            if let state::ReturnEvent::DlError(e) = act {
                eprintln!("DLError: {e:?}");
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
        let mut c = Client::new(Addr::new("M0THC-1"), Box::new(k));
        c.data.srt_default = std::time::Duration::from_millis(1);
        c.connect(&Addr::new("M0THC-2"))?;
        c.write(&vec![1, 2, 3])?;
        let reply = c.try_read()?;
        assert_eq!(
            reply,
            Packet {
                // TODO: is this even the bit set we expect
                src: Addr::new_bits("M0THC-2", true, false, false, false),
                dst: Addr::new_bits("M0THC-1", false, true, false, false),
                digipeater: vec![],
                rr_extseq: false,
                command_response: true,
                command_response_la: false,
                rr_dist1: false,
                packet_type: PacketType::Iframe(Iframe {
                    nr: 0,
                    ns: 0,
                    poll: false,
                    pid: 240,
                    payload: vec![16, 0xF0, 3, 2, 1, 162, 142],
                },),
            }
        );
        Ok(())
    }

    #[test]
    fn addr_serial() -> Result<()> {
        // TODO: test invalid calls.
        let a = Addr::new("M0THC-1").serialize(true, false, false, false);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 99]);
        assert_eq!(Addr::parse(&a)?.display(), "M0THC-1");

        let a = Addr::new("M0THC-2").serialize(false, true, false, false);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 100 + 0x80]);
        assert_eq!(Addr::parse(&a)?.display(), "M0THC-2");

        let a = Addr::new("M0THC-3").serialize(false, false, true, false);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 38]);
        assert_eq!(Addr::parse(&a)?.display(), "M0THC-3");

        let a = Addr::new("M0THC-4").serialize(false, false, false, true);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 72]);
        assert_eq!(Addr::parse(&a)?.display(), "M0THC-4");
        Ok(())
    }

    #[test]
    fn serialize_sabm() {
        let src = Addr::new("M0THC-1");
        let dst = Addr::new("M0THC-2");
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
            vec![154, 96, 168, 144, 134, 64, 228, 154, 96, 168, 144, 134, 64, 99, 63, 111, 212]
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
            vec![154, 96, 168, 144, 134, 64, 228, 154, 96, 168, 144, 134, 64, 99, 47, 238, 196]
        );
    }
}
