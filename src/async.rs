use std::collections::VecDeque;

use crate::state::{self, Event, ReturnEvent};
use crate::{Addr, Packet, PacketType};

use anyhow::{Error, Result};
use log::{debug, error};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

pub struct Client {
    state: Box<dyn state::State>,
    data: state::Data,
    port: tokio_serial::SerialStream,
    kiss_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    frame_rx: tokio::sync::mpsc::Receiver<Packet>,
    eof: bool,
    incoming: VecDeque<u8>,
}

fn kisser_read(ibuf: &mut VecDeque<u8>) -> Vec<Packet> {
    let mut ret = Vec::new();
    while let Some((a, b)) = crate::find_frame(ibuf) {
        if b - a < 14 {
            ibuf.drain(..(a + 1));
            continue;
        }
        let pb: Vec<_> = ibuf.iter().skip(a + 2).take(b - a - 2).cloned().collect();
        ibuf.drain(..b);
        let pb = crate::unescape(&pb);
        match Packet::parse(&pb) {
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

// Receive bytes, and respond on another channel with parsed frames.
async fn kisser(mut kiss_rx: mpsc::Receiver<Vec<u8>>, frame_tx: mpsc::Sender<Packet>) {
    let mut ibuf = VecDeque::new();
    let mut obuf: VecDeque<Packet> = VecDeque::new();

    // Loop until there's no more input.
    loop {
        // Send any outstanding frames.
        while !obuf.is_empty() && frame_tx.capacity() > 0 {
            let p = obuf.pop_front().unwrap();
            frame_tx.send(p).await.unwrap();
        }

        // If we're only reading.
        if obuf.is_empty() {
            match kiss_rx.recv().await {
                Some(bytes) => {
                    debug!("Got {} KISS bytes", bytes.len());
                    ibuf.extend(bytes);
                    obuf.extend(kisser_read(&mut ibuf));
                }
                None => break,
            }
            continue;
        }

        // If we're reading and writing.
        // This path has a packet copy.
        //
        // TODO: is there a way to avoid this copy?
        let to_send = obuf.front().cloned().unwrap(); // We know there's at least one.
        tokio::select! {
            bytes = kiss_rx.recv() => {
                match bytes {
                    Some(bytes) => {
                        debug!("Got {} KISS bytes", bytes.len());
                        ibuf.extend(bytes);
                        obuf.extend(kisser_read(&mut ibuf));
                    },
                    None => break,
                }
            },
            err = frame_tx.send(to_send) => {
                err.unwrap();
                obuf.pop_front();
            },
        }
    }
    for frame in obuf {
        if frame_tx.is_closed() {
            break;
        }
        if let Err(e) = frame_tx.send(frame).await {
            error!("Failed to send frame: {e}");
        }
    }
    eprintln!("KISS parser ending: {}", frame_tx.is_closed());
}

impl Client {
    pub async fn accept(me: Addr, port: tokio_serial::SerialStream) -> Result<Self> {
        let (kiss_tx, kiss_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(10);
        let (frame_tx, frame_rx) = tokio::sync::mpsc::channel::<Packet>(10);
        tokio::spawn(async move {
            kisser(kiss_rx, frame_tx).await;
        });
        let mut data = state::Data::new(me);
        data.able_to_establish = true;
        let mut cli = Self {
            kiss_tx,
            frame_rx,
            eof: false,
            incoming: VecDeque::new(),
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
        // TODO: change these limits to more reasonable ones, once kisser() is block free.
        let (kiss_tx, kiss_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(2);
        let (frame_tx, frame_rx) = tokio::sync::mpsc::channel::<Packet>(2);
        tokio::spawn(async move {
            kisser(kiss_rx, frame_tx).await;
        });
        let mut cli = Self {
            kiss_tx,
            frame_rx,
            eof: false,
            incoming: VecDeque::new(),
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
        tokio::select! {
            () = &mut t1 => {
                debug!("async con event: T1");
                self.actions(Event::T1).await?;
            },
            () = &mut t3 => {
                debug!("async con event: T3");
                self.actions(Event::T3).await?
            },
            frame = self.frame_rx.recv() => {
                let frame = frame.ok_or(Error::msg("KISS decoder closed channel"))?;
                debug!("async con event: frame: {:?}", frame.packet_type);
                self.actions_packet(&frame).await?;
            },
            res = self.port.read(&mut buf) => match res {
            Ok(n) => {
                debug!("Read {n} bytes from serial port");
                self.kiss_tx.send(buf[..n].to_vec()).await?;
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
