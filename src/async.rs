use crate::state::{self, Event};
use crate::Addr;

use anyhow::Result;
use tokio::io::AsyncReadExt;

pub struct Client {
    state: Box<dyn state::State>,
    data: state::Data,
    port: tokio_serial::SerialStream,
}

impl Client {
    pub async fn connect(me: Addr, peer: Addr, port: tokio_serial::SerialStream) -> Result<Self> {
        let mut cli = Self {
            port,
            state: state::new(),
            data: state::Data::new(me),
        };
        cli.action(Event::Connect(peer, false)).await;
        // TODO: await state becoming connected, after handling incoming packets.
        Ok(cli)
    }
    fn disconnect(&mut self) {
        // This must be sync, because it's called from drop(). Possibly we'll
        // need both a sync and async disconnect().
        todo!()
    }
    pub fn write(&mut self, data: &[u8]) {
        println!("TODO: write to serial: {data:?}");
    }
    pub async fn read(&mut self) -> Result<Vec<u8>> {
        loop {
            let timer1 = tokio::time::sleep(
                self.data
                    .t1
                    .remaining()
                    .unwrap_or(std::time::Duration::from_secs(86400)),
            );
            tokio::pin!(timer1);
            let timer3 = tokio::time::sleep(
                self.data
                    .t3
                    .remaining()
                    .unwrap_or(std::time::Duration::from_secs(86400)),
            );
            tokio::pin!(timer3);

            let mut buf = [0; 1024];
            tokio::select! {
                () = &mut timer1 => {self.action(Event::T1).await},
                () = &mut timer3 => {self.action(Event::T3).await},
                res = self.port.read(&mut buf) => match res {
                Ok(n) => println!("Read {n} bytes from serial port"),
                Err(e) => eprintln!("Error reading from serial port: {e:?}"),
                },
            }
        }
    }
    async fn action(&mut self, event: Event) {
        let (state, actions) = state::handle(&*self.state, &mut self.data, &event);
        if let Some(state) = state {
            let _ = std::mem::replace(&mut self.state, state);
        }
        for act in actions {
            println!("Do action: {act:?}");
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.disconnect()
    }
}
