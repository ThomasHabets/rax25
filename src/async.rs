use std::collections::VecDeque;

use crate::pcap::PcapWriter;
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

    pcap: Option<PcapWriter>,
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
    fn internal_new(data: state::Data, port: tokio_serial::SerialStream) -> Self {
        Self {
            eof: false,
            incoming: VecDeque::new(),
            incoming_frames: VecDeque::new(),
            incoming_kiss: VecDeque::new(),
            port,
            state: state::new(),
            data,
            pcap: None,
        }
    }

    pub async fn accept(me: Addr, port: tokio_serial::SerialStream) -> Result<Self> {
        let mut data = state::Data::new(me);
        data.able_to_establish = true;
        let mut cli = Self::internal_new(data, port);
        loop {
            cli.wait_event().await?;
            if cli.state.is_state_connected() {
                return Ok(cli);
            }
        }
    }
    pub async fn connect_capture(
        me: Addr,
        peer: Addr,
        port: tokio_serial::SerialStream,
        ext: bool,
        capture: Option<std::path::PathBuf>,
    ) -> Result<Self> {
        let mut cli = Self::internal_new(state::Data::new(me), port);
        if let Some(capture) = capture {
            cli.capture(capture)?;
        }
        cli.connect2(peer, ext).await
    }

    pub async fn connect(
        me: Addr,
        peer: Addr,
        port: tokio_serial::SerialStream,
        ext: bool,
    ) -> Result<Self> {
        Self::internal_new(state::Data::new(me), port)
            .connect2(peer, ext)
            .await
    }
    async fn connect2(mut self, peer: Addr, ext: bool) -> Result<Self> {
        self.actions(Event::Connect { addr: peer, ext }).await?;
        loop {
            self.wait_event().await?;
            debug!("State after waiting: {}", self.state.name());
            if self.state.is_state_connected() {
                return Ok(self);
            }
            if self.state.is_state_disconnected() {
                return Err(Error::msg("connection timed out"));
            }
        }
    }
    fn capture(&mut self, filename: std::path::PathBuf) -> Result<()> {
        let pcap = PcapWriter::create(filename)?;
        self.pcap = Some(pcap);
        Ok(())
    }
    fn extract_packets(&mut self) {
        self.incoming_frames
            .extend(kisser_read(&mut self.incoming_kiss, Some(self.data.ext())));
    }
    async fn wait_event(&mut self) -> Result<()> {
        let mut buf = [0; 1024];
        while let Some(p) = self.incoming_frames.pop_front() {
            debug!("processing packet {:?}", p.packet_type);
            if let Some(f) = &mut self.pcap {
                f.write(&p.serialize(self.data.ext()))?;
            }
            self.actions_packet(&p).await?;
            debug!(
                "post packet: {} {:?} {:?}",
                self.state.name(),
                self.data.t1.remaining(),
                self.data.t3.remaining()
            );
        }
        let (t1, t3) = self.timer_13();
        tokio::pin!(t1);
        tokio::pin!(t3);

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
        debug!(
            "async con post state: {} {:?} {:?}",
            self.state.name(),
            self.data.t1.remaining(),
            self.data.t3.remaining()
        );
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
                if let Some(f) = &mut self.pcap {
                    f.write(&frame)?;
                }
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
