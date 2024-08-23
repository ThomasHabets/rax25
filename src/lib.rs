pub mod state;

use anyhow::{Error, Result};

/// Source or dst addr.
#[derive(Debug, Clone, PartialEq)]
pub struct Addr {
    t: String,
}

impl Addr {
    pub fn new(s: &str) -> Self {
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
}
