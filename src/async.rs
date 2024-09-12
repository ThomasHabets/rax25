use std::collections::VecDeque;

use crate::state::{self, Event, ReturnEvent};
use crate::{Addr, Packet, PacketType};

use anyhow::{Error, Result};
use log::debug;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

pub struct Client {
    state: Box<dyn state::State>,
    data: state::Data,
    port: tokio_serial::SerialStream,
    eof: bool,
    incoming: VecDeque<u8>,
    incoming_kiss: VecDeque<u8>,
    incoming_frames: VecDeque<Packet>,
}

fn kisser_read(ibuf: &mut VecDeque<u8>, ext: Option<bool>) -> Vec<Packet> {
    let mut ret = Vec::new();
    while let Some((a, b)) = crate::find_frame(ibuf) {
        if b - a < 14 {
            ibuf.drain(..(a + 1));
            continue;
        }
        let pb: Vec<_> = ibuf.iter().skip(a + 2).take(b - a - 2).cloned().collect();
        ibuf.drain(..b);
        let pb = crate::unescape(&pb);
        match Packet::parse(&pb, ext) {
            Ok(packet) => {
                debug!("parsed {packet:?}");
                ret.push(packet);
            }
            Err(e) => {
                debug!("Failed to parse packet: {e:?}");
            }
        }
    }
    ret
}

impl Client {
    pub async fn accept(me: Addr, port: tokio_serial::SerialStream) -> Result<Self> {
        let mut data = state::Data::new(me);
        data.able_to_establish = true;
        let mut cli = Self {
            eof: false,
            incoming: VecDeque::new(),
            incoming_frames: VecDeque::new(),
            incoming_kiss: VecDeque::new(),
            port,
            state: state::new(),
            data,
        };
        loop {
            cli.wait_event().await?;
            if cli.state.is_state_connected() {
                return Ok(cli);
            }
        }
    }
    pub async fn connect(
        me: Addr,
        peer: Addr,
        port: tokio_serial::SerialStream,
        ext: bool,
    ) -> Result<Self> {
        let mut cli = Self {
            eof: false,
            incoming: VecDeque::new(),
            incoming_frames: VecDeque::new(),
            incoming_kiss: VecDeque::new(),
            port,
            state: state::new(),
            data: state::Data::new(me),
        };
        cli.actions(Event::Connect(peer, ext)).await?;
        loop {
            cli.wait_event().await?;
            debug!("State after waiting: {}", cli.state.name());
            if cli.state.is_state_connected() {
                return Ok(cli);
            }
            if cli.state.is_state_disconnected() {
                return Err(Error::msg("connection timed out"));
            }
        }
    }
    fn extract_packets(&mut self) {
        self.incoming_frames
            .extend(kisser_read(&mut self.incoming_kiss, Some(self.data.ext())));
    }
    async fn wait_event(&mut self) -> Result<()> {
        let (t1, t3) = self.timer_13();
        tokio::pin!(t1);
        tokio::pin!(t3);

        let mut buf = [0; 1024];
        debug!(
            "async con pre state: {} {:?} {:?}",
            self.state.name(),
            self.data.t1.remaining(),
            self.data.t3.remaining()
        );
        while let Some(p) = self.incoming_frames.pop_front() {
            self.actions_packet(&p).await?;
        }
        tokio::select! {
            () = &mut t1 => {
                debug!("async con event: T1");
                self.actions(Event::T1).await?;
            },
            () = &mut t3 => {
                debug!("async con event: T3");
                self.actions(Event::T3).await?
            },
            res = self.port.read(&mut buf) => match res {
            Ok(n) => {
                debug!("Read {n} bytes from serial port");
                let buf = &buf[..n];
                self.incoming_kiss.extend(buf);
                self.extract_packets();
            },
            Err(e) => eprintln!("Error reading from serial port: {e:?}"),
            },
        }
        debug!("async con post state: {}", self.state.name());
        Ok(())
    }
    async fn actions_packet(&mut self, packet: &Packet) -> Result<()> {
        match &packet.packet_type {
            PacketType::Sabm(p) => self.actions(state::Event::Sabm(p.clone(), packet.src.clone())),
            PacketType::Sabme(p) => {
                self.actions(state::Event::Sabme(p.clone(), packet.src.clone()))
            }
            PacketType::Ua(ua) => self.actions(state::Event::Ua(ua.clone())),
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
        .await
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        // TODO: wait for the UA
        self.actions(Event::Disconnect).await
    }

    fn sync_disconnect(&mut self) {
        if !self.state.is_state_disconnected() {
            eprintln!("TODO: sync_disconnect")
        }
    }
    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        self.actions(Event::Data(data.to_vec())).await
    }
    fn timer_13(&self) -> (tokio::time::Sleep, tokio::time::Sleep) {
        let timer1 = tokio::time::sleep(
            self.data
                .t1
                .remaining()
                .unwrap_or(std::time::Duration::from_secs(86400)),
        );
        let timer3 = tokio::time::sleep(
            self.data
                .t3
                .remaining()
                .unwrap_or(std::time::Duration::from_secs(86400)),
        );
        (timer1, timer3)
    }

    pub async fn read(&mut self) -> Result<Vec<u8>> {
        loop {
            self.wait_event().await?;
            if self.incoming.is_empty() && self.eof {
                return Ok(vec![]);
            }
            if !self.incoming.is_empty() {
                let ret: Vec<_> = self.incoming.iter().cloned().collect();
                self.incoming.clear();
                return Ok(ret);
            }
        }
    }

    async fn actions(&mut self, event: Event) -> Result<()> {
        let (state, actions) = state::handle(&*self.state, &mut self.data, &event);
        if let Some(state) = state {
            let _ = std::mem::replace(&mut self.state, state);
        }
        for act in actions {
            match &act {
                ReturnEvent::DlError(e) => eprintln!("DLError: {e:?}"),
                ReturnEvent::Data(res) => match res {
                    state::Res::None => {}
                    state::Res::EOF => self.eof = true,
                    state::Res::Some(d) => self.incoming.extend(d),
                },
                _ => {
                    // println!("Do action: {act:?}");
                }
            }
            if let Some(frame) = act.serialize(self.data.ext()) {
                let frame = crate::escape(&frame);
                self.port.write_all(&frame).await?;
                self.port.flush().await?;
            }
        }
        Ok(())
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.sync_disconnect()
    }
}
