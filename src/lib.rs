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
pub struct Sabm {
    src: Addr,
    dst: Addr,
    poll: bool,
}

// TODO: add digipeater stuff.
fn packet_start(src: &Addr, dst: &Addr, control: u8, reserve: usize) -> Vec<u8> {
    let mut ret = Vec::with_capacity(reserve + 8 + 8 + 1);
    let digipeaters: Vec<u8> = vec![];
    ret.extend(dst.serialize(false, false, false, false));
    ret.extend(src.serialize(false, digipeaters.is_empty(), false, false));
    ret.push(control);
    ret
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

impl Sabm {
    pub fn serialize(&self) -> Vec<u8> {
        packet_start(
            &self.src,
            &self.dst,
            CONTROL_SABM | if self.poll { 0b0001_0000 } else { 0 },
            0,
        )
    }
}

#[derive(Debug, PartialEq)]
pub struct Sabme {
    src: Addr,
    dst: Addr,
    poll: bool,
}

impl Sabme {
    pub fn serialize(&self) -> Vec<u8> {
        todo!()
    }
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

impl Iframe {
    pub fn serialize(&self) -> Vec<u8> {
        todo!()
    }
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

impl Disc {
    pub fn serialize(&self) -> Vec<u8> {
        todo!()
    }
}

pub struct Kiss {}

// For now this is a KISS interface. But it needs to be changed to allow multiplexing.
impl Kiss {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        eprintln!("TODO: send {frame:?}");
        Ok(())
    }
    fn recv_timeout(&mut self, _timeout: std::time::Duration) -> Result<Vec<u8>> {
        Err(Error::msg("connection timeout"))
    }
}

pub struct Client {
    kiss: Kiss,
    data: state::Data,
    state: Box<dyn state::State>,
}
impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn new() -> Self {
        Self {
            kiss: Kiss {},
            data: state::Data::new(),
            state: state::new(),
        }
    }
    pub fn connect(&mut self, addr: &Addr) -> Result<()> {
        self.actions(state::Event::Connect(addr.clone()));
        let st = std::time::Instant::now();
        let deadline = st + std::time::Duration::from_secs(10); // TODO: configurable.
        loop {
            let _packet = self
                .kiss
                .recv_timeout(deadline - std::time::Instant::now())?;
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
    fn client() -> Result<()> {
        let mut c = Client::new();
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
            Sabm {
                src: src.clone(),
                dst: dst.clone(),
                poll: true
            }
            .serialize(),
            vec![154, 96, 168, 144, 134, 64, 100, 154, 96, 168, 144, 134, 64, 226, 63]
        );
        assert_eq!(
            Sabm {
                src,
                dst,
                poll: false
            }
            .serialize(),
            vec![154, 96, 168, 144, 134, 64, 100, 154, 96, 168, 144, 134, 64, 226, 47]
        );
    }
}
