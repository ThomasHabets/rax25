use anyhow::{Error, Result};
use log::debug;

mod fcs;
pub mod state;

/// Source or dst addr.
#[derive(Debug, Clone, PartialEq)]
pub struct Addr {
    t: String,
}

impl Addr {
    pub fn new(s: &str) -> Self {
        // TODO: check format
        Self { t: s.to_string() }
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
        Ok(Self { t: r })
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
            _ => todo!(),
        };
        let crc = fcs::fcs(&ret);
        ret.push(crc[0]);
        ret.push(crc[1]);
        ret
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 17 {
            return Err(Error::msg(format!(
                "packet too short: {} bytes",
                bytes.len()
            )));
        }
        // TODO: check FCS.
        let bytes = &bytes[..(bytes.len() - 2)];
        let dst = Addr::parse(&bytes[0..7])?;
        let src = Addr::parse(&bytes[7..14])?;

        Ok(Packet {
            src,
            dst,
            command_response: true,
            command_response_la: false,
            rr_dist1: false,
            rr_extseq: false,
            digipeater: vec![],
            packet_type: PacketType::Ua(Ua { poll: true }),
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

#[derive(Debug, PartialEq)]
pub struct Iframe {
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
        self.queue
            .push_back(Self::make_ua(packet.dst.clone(), packet.src.clone()).serialize());
        Ok(())
    }
    fn recv_timeout(&mut self, _timeout: std::time::Duration) -> Result<Option<Vec<u8>>> {
        Ok(self.queue.pop_front())
    }
}

pub struct Kiss {}

// For now this is a KISS interface. But it needs to be changed to allow multiplexing.
impl Kisser for Kiss {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        eprintln!("TODO: send {frame:?}");
        Ok(())
    }
    fn recv_timeout(&mut self, timeout: std::time::Duration) -> Result<Option<Vec<u8>>> {
        std::thread::sleep(timeout);
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
    fn client_timeout() -> Result<()> {
        let k = FakeKiss::default();
        let mut c = Client::new(Addr::new("M0THC-1"), Box::new(k));
        c.data.srt_default = std::time::Duration::from_millis(1);
        c.connect(&Addr::new("M0THC-2"))?;
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
