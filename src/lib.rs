pub mod state;

use state::Addr;

pub struct Client {
    data: state::Data,
    state: Box<dyn state::State>,
}

impl Client {
    pub fn new() -> Self {
        Self {
            data: state::Data::new(),
            state: state::new(),
        }
    }
    pub fn connect(&mut self, addr: &Addr) {
        let (state, actions) = state::handle(&self.state, &mut self.data, &state::Event::Connect(addr.clone()));
        self.actions(state, &actions);
    }
    pub fn actions(&mut self, state: Option<Box<dyn state::State>>, acts: &[state::ReturnEvent]) {
	if let Some(state) = state {
	    let _ = std::mem::replace(&mut self.state, state);
	}
	for act in acts {
	    eprintln!("Action: {:?}", act.serialize());
	}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client() {
        let mut c = Client::new();
        c.connect(&Addr::new("M0THC-2"));
	assert!(false);
    }
}
