pub mod state;

use anyhow::{Error, Result};

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
            _ => todo!(),
        };
        ret
    }
}

#[derive(Debug, PartialEq)]
pub struct Sabme {
    poll: bool,
}

#[derive(Debug, PartialEq)]
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

pub struct Kiss {}

// For now this is a KISS interface. But it needs to be changed to allow multiplexing.
impl Kiss {
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
    kiss: Kiss,
    pub(crate) data: state::Data,
    state: Box<dyn state::State>,
}

impl Client {
    pub fn new(me: Addr) -> Self {
        Self {
            kiss: Kiss {},
            data: state::Data::new(me),
            state: state::new(),
        }
    }
    pub fn connect(&mut self, addr: &Addr) -> Result<()> {
        self.actions(state::Event::Connect(addr.clone()));
        loop {
            let dead = self.data.next_timer_remaining();
            let _packet = self
                .kiss
                .recv_timeout(dead.unwrap_or(std::time::Duration::from_secs(60)));
            if self.data.t1_expired() {
                self.actions(state::Event::T1);
            }
            if self.data.t3_expired() {
                self.actions(state::Event::T3);
            }
            // TODO: stop using string comparison.
            if self.state.name() == "Disconnected" {
                dbg!("connection timeout");
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
        let mut c = Client::new(Addr::new("M0THC-1"));
        c.data.srt_default = std::time::Duration::from_millis(1);
        assert![matches![c.connect(&Addr::new("M0THC-2")), Err(_)]];
        Ok(())
    }

    #[test]
    fn addr_serial() -> Result<()> {
        // TODO: test invalid calls.
        assert_eq!(
            Addr::new("M0THC-1").serialize(true, false, false, false),
            vec![154, 96, 168, 144, 134, 64, 99]
        );
        assert_eq!(
            Addr::new("M0THC-2").serialize(false, true, false, false),
            vec![154, 96, 168, 144, 134, 64, 100 + 0x80]
        );
        assert_eq!(
            Addr::new("M0THC-3").serialize(false, false, true, false),
            vec![154, 96, 168, 144, 134, 64, 38]
        );
        assert_eq!(
            Addr::new("M0THC-4").serialize(false, false, false, true),
            vec![154, 96, 168, 144, 134, 64, 72]
        );
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
            vec![154, 96, 168, 144, 134, 64, 228, 154, 96, 168, 144, 134, 64, 99, 63]
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
            vec![154, 96, 168, 144, 134, 64, 228, 154, 96, 168, 144, 134, 64, 99, 47]
        );
    }
}
