use anyhow::{Error, Result};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use log::debug;
use std::io::{Read, Write};

mod fcs;
pub mod state;

const USE_FCS: bool = false;

mod client;
pub use client::Client;

/// AX.25 address.
///
/// The encoding for an AX.25 address includes some extra bits, so they're
/// included here. That way they can be serialized and parsed fully in and
/// out of the struct.
///
/// This may not be the best idea, so is worth revisiting.
#[derive(Debug, Clone, PartialEq)]
pub struct Addr {
    t: String,
    rbit_ext: bool,
    highbit: bool,
    lowbit: bool,
    rbit_dama: bool,
}

impl Addr {
    /// Create a new Addr from string. The extra bits are all clear.
    pub fn new(s: &str) -> Result<Self> {
        let s = s.to_uppercase();
        let re = regex::Regex::new(r"^[A-Z0-9]{3,6}(?:-(?:[0-9]|1[0-5]))?$")
            .expect("can't happen: Regex compile fail");
        if !re.is_match(&s) {
            return Err(Error::msg(format!("invalid callsign: {s}")));
        }
        Ok(Self {
            t: s,
            rbit_ext: false,
            highbit: false,
            lowbit: false,
            rbit_dama: false,
        })
    }

    /// Create a new Addr from string and the extra bits.
    pub fn new_bits(
        s: &str,
        lowbit: bool,
        highbit: bool,
        rbit_ext: bool,
        rbit_dama: bool,
    ) -> Result<Self> {
        let mut a = Self::new(s)?;
        a.lowbit = lowbit;
        a.highbit = highbit;
        a.rbit_ext = rbit_ext;
        a.rbit_dama = rbit_dama;
        Ok(a)
    }

    /// Get just the callsign & SSID as a string, not the extra bits.
    #[must_use]
    pub fn call(&self) -> &str {
        &self.t
    }

    /// Parse the callsign and the extra bits from the packet format.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 7 {
            return Err(Error::msg(format!(
                "invalid serialized callsign: {bytes:?}"
            )));
        }
        let call = {
            let call = bytes
                .iter()
                .take(6)
                .map(|&c| (c >> 1) as char)
                .collect::<String>()
                .trim_end()
                .to_string();
            let ssid = (bytes[6] >> 1) & 15;
            if ssid > 0 {
                call + "-" + &ssid.to_string()
            } else {
                call
            }
        };
        Self::new_bits(
            &call,
            bytes[6] & 1 != 0,
            bytes[6] & 0x80 != 0,
            bytes[6] & 0b0100_0000 == 0,
            bytes[6] & 0b0010_0000 == 0,
        )
    }

    /// Serialize the callsign and SSID, plus explicit bits.
    #[must_use]
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
}

/// AX.25 packet, of all types.
///
/// Maybe this should be replaced by a protobuf.
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

/// All packet types.
#[derive(Debug, PartialEq)]
pub enum PacketType {
    Sabm(Sabm),
    Sabme(Sabme),
    Ua(Ua),
    Dm(Dm),
    Disc(Disc),
    Iframe(Iframe),
    Rr(Rr),
    Rnr(Rnr),
    Rej(Rej),
    Srej(Srej),
    Frmr(Frmr),
    Xid(Xid),
    Ui(Ui),
    Test(Test),
}

/// SABM - Set Asynchronous Balanced Mode (4.3.3.1, page 23)
#[derive(Clone, Debug, PartialEq)]
pub struct Sabm {
    poll: bool,
}

/// SAMBE - Set Asynchronous Balanced Mode Extended (4.3.3.2, page 23)
#[derive(Clone, Debug, PartialEq)]
pub struct Sabme {
    poll: bool,
}

/// RR - Receiver Ready (4.3.2.1, page 21)
///
/// Basically an ACK.
#[derive(Debug, PartialEq, Clone)]
pub struct Rr {
    poll: bool,
    nr: u8,
}

/// REJ - Reject (4.3.2.3, page 21)
///
/// Unclear why this is even needed. Couldn't RR with NR older than last sent
/// be equally eager to retransmit?
#[derive(Debug, PartialEq, Clone)]
pub struct Rej {
    poll: bool,
    nr: u8,
}

/// SREJ - Selective reject (4.3.2.4, page 21)
///
/// Request retransmissions of a single iframe.
#[derive(Debug, PartialEq, Clone)]
pub struct Srej {
    poll: bool,
    nr: u8,
}

/// FRMR - A deprecated error signaling (4.3.3.9, page 28)
///
/// The AX.25 2.2 spec deprecates this, and says to not generate these frames. But
/// it does specify what to do when receiving one.
#[derive(Debug, PartialEq, Clone)]
pub struct Frmr {
    poll: bool,
}

/// Test - Test frame (4.3.3.8, page 28)
///
/// It's ping, basically. The payload is mirrorred back, or (if there's not
/// enough room to store the payload), an empty response is returned.
///
/// The intended use of the poll flag here is unclear.
#[derive(Debug, PartialEq, Clone)]
pub struct Test {
    poll: bool,
    payload: Vec<u8>,
}

/// XID - Exchange Identification (4.3.3.7, page 24)
///
/// ISO 8885 exchange of capabilities, like extended sequence numbers,
/// max IFRAME size ("MTU"), and lots of other stuff.
///
/// TODO: Currently not implemented.
#[derive(Debug, PartialEq, Clone)]
pub struct Xid {
    poll: bool,
}

/// RNR - Receiver Not Ready (4.3.2.2, page 21)
///
/// Like RR, but asks the sender to not send more data for now.
/// The TCP version of this would be a closed receiver window.
#[derive(Debug, PartialEq, Clone)]
pub struct Rnr {
    poll: bool,
    nr: u8,
}

/// UA - Unnumbered Ack (4.3.3.4, page 23)
///
/// Acknowledge of things that don't have sequence numbers. Like SABM(E)
/// and DISC.
///
/// The equivalent of both the replying FIN and the SYN|ACK in TCP.
/// Probably not a good idea to use the same message for these two very
/// different events, since it's more "yeah, whatever, I hear you", but
/// not acknowledging if you heard "let's go" or "close down".
#[derive(Debug, PartialEq, Clone)]
pub struct Ua {
    poll: bool,
}

/// IFRAME - Information Frame (4.3.1, page 19)
///
/// Carries information. Obviously. Really, this could probably have been
/// merged with RR/RNR, even if it means empty payload. That's what
/// TCP does.
#[derive(Clone, Debug, PartialEq)]
pub struct Iframe {
    nr: u8,
    ns: u8,
    poll: bool,
    pid: u8,
    payload: Vec<u8>,
}

/// UI - Unnumbered Information (4.3.3.6, page 24)
///
/// Information frames outside of the sequential data flow.
/// Can be used whether a connection is established or not.
/// Disconnected UIs power APRS.
///
/// APRS doesn't use "push" for ACKs, but when unicasted
/// it could. A DM should be returned when push is set.
#[derive(Clone, Debug, PartialEq)]
pub struct Ui {
    push: bool,
    payload: Vec<u8>,
}

/// DM - Disconnected Mode (4.3.3.5, page 23)
///
/// The reply if the incoming packet implies a connection is active, or if
/// a SABM(E) was received and nothing was ready to receive it.
///
/// Basically a TCP RST.
#[derive(Clone, Debug, PartialEq)]
pub struct Dm {
    poll: bool,
}

/// DISC - Disconnect (4.3.3.3, page 23)
///
/// End the connection. A DISC is acked with a UA packet, which seems
/// silly. Replying with DISC would make more sense, but hey ho.
#[derive(Clone, Debug, PartialEq)]
pub struct Disc {
    poll: bool,
}

// Unnumbered frames. Ending in 11.
#[allow(clippy::unusual_byte_groupings)]
const CONTROL_SABM: u8 = 0b001_0_11_11;
#[allow(clippy::unusual_byte_groupings)]
const CONTROL_SABME: u8 = 0b011_0_11_11;
#[allow(clippy::unusual_byte_groupings)]
const CONTROL_UI: u8 = 0b000_0_00_11;
#[allow(clippy::unusual_byte_groupings)]
const CONTROL_DISC: u8 = 0b010_0_00_11;
#[allow(clippy::unusual_byte_groupings)]
const CONTROL_DM: u8 = 0b0000_1111;
const CONTROL_UA: u8 = 0b0110_0011;
const CONTROL_TEST: u8 = 0b1110_0011;
const CONTROL_XID: u8 = 0b1010_1111;
const CONTROL_FRMR: u8 = 0b1000_0111;

// Supervisor frames. Ending in 01.
const CONTROL_RR: u8 = 0b0000_0001;
const CONTROL_RNR: u8 = 0b0000_0101;
const CONTROL_REJ: u8 = 0b0000_1001;
const CONTROL_SREJ: u8 = 0b0000_1101;

// Iframes end in 0.
const CONTROL_IFRAME: u8 = 0b0000_0000;

// Masks.
const CONTROL_POLL: u8 = 0b0001_0000;
const NR_MASK: u8 = 0b1110_0000;
const TYPE_MASK: u8 = 0b0000_0011;
const NO_L3: u8 = 0xF0;

impl Packet {
    /// Serialize a packet, either as standard mod-8, or extended mod-128.
    #[must_use]
    pub fn serialize(&self, ext: bool) -> Vec<u8> {
        let mut ret = Vec::with_capacity(
            14 + 2
                + if let PacketType::Iframe(s) = &self.packet_type {
                    s.payload.len() + 1
                } else {
                    0
                },
        );
        ret.extend(
            self.dst
                .serialize(false, self.command_response, self.rr_dist1, false),
        );
        assert_ne!(self.command_response, self.command_response_la);
        ret.extend(self.src.serialize(
            self.digipeater.is_empty(),
            self.command_response_la,
            ext, // Setting this bit for extseq seems to be a de facto standard.
            false,
        ));

        match &self.packet_type {
            // U frames. Control always one byte.
            PacketType::Sabm(s) => {
                if ext {
                    ret.push(CONTROL_SABME | if s.poll { CONTROL_POLL } else { 0 });
                } else {
                    ret.push(CONTROL_SABM | if s.poll { CONTROL_POLL } else { 0 });
                }
            }
            PacketType::Sabme(s) => ret.push(CONTROL_SABME | if s.poll { CONTROL_POLL } else { 0 }),
            PacketType::Ua(s) => ret.push(CONTROL_UA | if s.poll { CONTROL_POLL } else { 0 }),
            PacketType::Disc(disc) => {
                ret.push(CONTROL_DISC | if disc.poll { CONTROL_POLL } else { 0 })
            }
            PacketType::Dm(s) => ret.push(CONTROL_DM | if s.poll { CONTROL_POLL } else { 0 }),
            // TODO: FRMR data too.
            PacketType::Frmr(s) => ret.push(CONTROL_FRMR | if s.poll { CONTROL_POLL } else { 0 }),
            // TODO: UI data too.
            PacketType::Ui(s) => ret.push(CONTROL_UI | if s.push { CONTROL_POLL } else { 0 }),
            // TODO: XID data too.
            PacketType::Xid(s) => ret.push(CONTROL_XID | if s.poll { CONTROL_POLL } else { 0 }),
            PacketType::Test(s) => {
                ret.push(CONTROL_TEST | if s.poll { CONTROL_POLL } else { 0 });
                ret.extend(&s.payload);
            }

            // S frames.
            PacketType::Rr(s) => {
                if ext {
                    ret.push(CONTROL_RR);
                    ret.push((s.nr << 1) & 0xFE | if s.poll { 1 } else { 0 });
                } else {
                    ret.push(
                        CONTROL_RR
                            | if s.poll { CONTROL_POLL } else { 0 }
                            | ((s.nr << 5) & NR_MASK),
                    );
                }
            }
            PacketType::Rnr(s) => {
                if ext {
                    ret.push(CONTROL_RNR);
                    ret.push((s.nr << 1) & 0xFE | if s.poll { 1 } else { 0 });
                } else {
                    ret.push(
                        CONTROL_RNR
                            | if s.poll { CONTROL_POLL } else { 0 }
                            | ((s.nr << 5) & NR_MASK),
                    );
                }
            }
            PacketType::Rej(s) => {
                if ext {
                    ret.push(CONTROL_REJ);
                    ret.push((s.nr << 1) & 0xFE | if s.poll { 1 } else { 0 });
                } else {
                    ret.push(CONTROL_REJ | if s.poll { CONTROL_POLL } else { 0 });
                }
            }
            PacketType::Srej(s) => {
                if ext {
                    ret.push(CONTROL_SREJ);
                    ret.push((s.nr << 1) & 0xFE | if s.poll { 1 } else { 0 });
                } else {
                    ret.push(CONTROL_SREJ | if s.poll { CONTROL_POLL } else { 0 });
                }
            }
            PacketType::Iframe(iframe) => {
                if ext {
                    ret.push(CONTROL_IFRAME | ((iframe.ns << 1) & 0xFE));
                    ret.push((iframe.nr << 1) & 0xFE | if iframe.poll { 1 } else { 0 });
                } else {
                    ret.push(
                        CONTROL_IFRAME
                            | if iframe.poll { CONTROL_POLL } else { 0 }
                            | ((iframe.nr << 5) & 0b1110_0000)
                            | ((iframe.ns << 1) & 0b0000_1110),
                    );
                }
                ret.push(iframe.pid);
                ret.extend(&iframe.payload);
            }
        };
        if USE_FCS {
            let crc = fcs::fcs(&ret);
            ret.push(crc[0]);
            ret.push(crc[1]);
        }
        ret
    }

    /// Parse packet from bytes.
    ///
    /// Source address `rbit_ext` is used to indicate that the packet is using
    /// the mod-128 extended format, just like the Linux kernel does.
    ///
    /// That doesn't actually appear to be a standard, so we should probably
    /// allow the caller to override, forcing use of extended or non-extended.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let do_fcs = USE_FCS;
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

        let ext = src.rbit_ext;

        // TODO: parse digipeater.
        let control1 = bytes[14];
        let (poll, nr, ns, bytes) = {
            if !ext || control1 & TYPE_MASK == 3 {
                // NOTE: ns/nr will be nonsense for U frames.
                // ns will be nonsense for S frames.
                (
                    control1 & CONTROL_POLL == CONTROL_POLL,
                    (control1 >> 5) & 7,
                    (control1 >> 1) & 7,
                    &bytes[15..],
                )
            } else {
                if bytes.len() < 16 {
                    return Err(Error::msg("AX.25 in ext mode, but S/U frame is too short"));
                }
                let control2 = bytes[15];
                (
                    control2 & 1 == 1,
                    (control2 >> 1) & 127,
                    (control1 >> 1) & 127,
                    &bytes[16..],
                )
            }
        };
        Ok(Packet {
            src: src.clone(),
            dst: dst.clone(),
            command_response: dst.highbit,
            command_response_la: src.highbit,
            rr_dist1: dst.rbit_ext,
            rr_extseq: ext,
            digipeater: vec![],
            packet_type: match control1 & TYPE_MASK {
                // I frames. Second control byte, with NR and NS.
                // TODO: confirm pid is NO_L3
                0 | 2 => PacketType::Iframe(Iframe {
                    ns,
                    nr,
                    poll,
                    pid: NO_L3,
                    payload: bytes[1..].to_vec(),
                }),
                // S frames. Second control byte, with NR.
                1 => match control1 & !NR_MASK & !CONTROL_POLL {
                    CONTROL_RR => PacketType::Rr(Rr { nr, poll }),
                    CONTROL_RNR => PacketType::Rnr(Rnr { nr, poll }),
                    CONTROL_REJ => PacketType::Rej(Rej { nr, poll }),
                    CONTROL_SREJ => PacketType::Srej(Srej { nr, poll }),
                    _ => panic!("Impossible logic error: {control1} failed to be supervisor"),
                },
                // U frames. No second control byte.
                3 => match !CONTROL_POLL & control1 {
                    CONTROL_SABME => PacketType::Sabme(Sabme { poll }),
                    CONTROL_SABM => PacketType::Sabm(Sabm { poll }),
                    CONTROL_UA => PacketType::Ua(Ua { poll }),
                    CONTROL_DISC => PacketType::Disc(Disc { poll }),
                    CONTROL_DM => PacketType::Dm(Dm { poll }),
                    CONTROL_FRMR => PacketType::Frmr(Frmr { poll }),
                    CONTROL_UI => PacketType::Ui(Ui {
                        push: poll,
                        payload: bytes.to_vec(),
                    }),
                    CONTROL_XID => PacketType::Xid(Xid { poll }),
                    CONTROL_TEST => PacketType::Test(Test {
                        poll,
                        payload: bytes.to_vec(),
                    }),
                    c => todo!("Control {c:b} not implemented"),
                },
                _ => panic!("Logic error: {control1} & 3 > 3"),
            },
        })
    }
}

/// Hub packet serializer/deserializer.
///
/// Hub reads and writes packets. Normally to a KISS serial port. But
/// ideally something more clevel with priority queues and mux-capability.
///
/// Then again that more clever system could just be freestanding, and expose
/// KISS as an interface to it.
pub trait Hub {
    /// Send frame. May block.
    ///
    /// The provided frame must be a complete AX.25 frame, without FEND or
    /// escaping.
    fn send(&mut self, frame: &[u8]) -> Result<()>;

    /// Try receiving a frame.
    ///
    /// Ok(None) means timeout.
    fn recv_timeout(&mut self, timeout: std::time::Duration) -> Result<Option<Vec<u8>>>;

    /// Clone a kisser.
    /// All packets get delivered to all clones.
    fn clone(&self) -> Box<dyn Hub>;
}

#[cfg(test)]
#[derive(Default, Debug)]
struct FakeKiss {
    ext: bool,
    queue: std::collections::VecDeque<Vec<u8>>,
}

#[cfg(test)]
impl FakeKiss {
    #[must_use]
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

    #[must_use]
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
impl Hub for FakeKiss {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        let packet = Packet::parse(frame)?;
        match &packet.packet_type {
            PacketType::Sabm(_) | PacketType::Sabme(_) => {
                self.queue.push_back(
                    Self::make_ua(packet.dst.clone(), packet.src.clone()).serialize(self.ext),
                );
            }
            PacketType::Iframe(_) => {
                self.queue.push_back(
                    Self::make_iframe(packet.dst.clone(), packet.src.clone(), vec![3, 2, 1])
                        .serialize(self.ext),
                );
            }
            PacketType::Disc(_) => {
                self.queue.push_back(
                    Self::make_ua(packet.dst.clone(), packet.src.clone()).serialize(self.ext),
                );
            }
            _ => {
                eprintln!("FakeKiss: Unexpected packet {packet:?}");
            }
        }
        Ok(())
    }
    fn recv_timeout(&mut self, _timeout: std::time::Duration) -> Result<Option<Vec<u8>>> {
        Ok(self.queue.pop_front())
    }
    fn clone(&self) -> Box<dyn Hub> {
        Box::new(FakeKiss::default())
    }
}

#[derive(Clone)]
pub struct BusMessage {
    sender: usize,
    data: Vec<u8>,
}

pub struct BusHub {
    rx: bus::BusReader<BusMessage>,
    bus: Arc<Mutex<bus::Bus<BusMessage>>>,
}

impl BusHub {
    pub fn new(bus: Arc<Mutex<bus::Bus<BusMessage>>>) -> Self {
        let rx = {
            let bus = bus.lock();
            bus.unwrap().add_rx()
        };
        Self { rx, bus }
    }
}

impl Hub for BusHub {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        let bus = self.bus.lock();
        bus.unwrap()
            .try_broadcast(BusMessage {
                sender: 0,
                data: frame.to_vec(),
            })
            .map_err(|_| Error::msg("failed to broadcast"))?;
        Ok(())
    }

    fn recv_timeout(&mut self, timeout: std::time::Duration) -> Result<Option<Vec<u8>>> {
        Ok(Some(self.rx.recv_timeout(timeout)?.data))
    }

    fn clone(&self) -> Box<dyn Hub> {
        Box::new(Self::new(self.bus.clone()))
    }
}

/// Kiss reads and writes packets on a KISS serial port.
///
/// https://en.wikipedia.org/wiki/KISS_(amateur_radio_protocol)
pub struct Kiss {
    buf: std::collections::VecDeque<u8>,
    port: Box<dyn serialport::SerialPort>,
}

impl Kiss {
    /// Create new Kiss connected to the named port.
    ///
    /// Currently hard coded to 9600bps 8N1.
    pub fn new(port: &str) -> Result<Self> {
        //            let mut stream = std::net::TcpStream::connect("127.0.0.1:8001")?;
        let port = serialport::new(port, 9600)
            .flow_control(serialport::FlowControl::None)
            .parity(serialport::Parity::None)
            .data_bits(serialport::DataBits::Eight)
            .stop_bits(serialport::StopBits::One)
            .open()?;
        port.clear(serialport::ClearBuffer::All)?;
        Ok(Self {
            buf: std::collections::VecDeque::new(),
            port,
            //        port: Box::new(stream),
        })
    }
}

static BUSKISS_ID: AtomicUsize = AtomicUsize::new(1);

/// Send data between bus and KISS interface.
pub struct BusKiss {
    rx: bus::BusReader<BusMessage>,
    bus: Arc<Mutex<bus::Bus<BusMessage>>>,
    kiss: Kiss,
    id: usize,
}
impl BusKiss {
    pub fn new(port: &str, bus: Arc<Mutex<bus::Bus<BusMessage>>>) -> Result<Self> {
        let rx = {
            let bus = bus.lock();
            bus.unwrap().add_rx()
        };
        Ok(Self {
            id: BUSKISS_ID.fetch_add(1, Ordering::SeqCst),
            kiss: Kiss::new(port)?,
            rx,
            bus,
        })
    }
    pub fn run(&mut self) {
        loop {
            let d = std::time::Duration::from_millis(10);
            if let Ok(rx) = self.rx.recv_timeout(d) {
                if rx.sender != self.id {
                    self.kiss.send(&rx.data).unwrap();
                }
            }
            if let Ok(Some(rx)) = self.kiss.recv_timeout(d) {
                self.bus
                    .lock()
                    .unwrap()
                    .try_broadcast(BusMessage {
                        sender: self.id,
                        data: rx,
                    })
                    .map_err(|_| Error::msg("queue full"))
                    .expect("failed to broadcast");
            }
        }
    }
}

const KISS_FEND: u8 = 0xC0;
const KISS_FESC: u8 = 0xDB;
const KISS_TFEND: u8 = 0xDC;
const KISS_TFESC: u8 = 0xDD;

/// Escape KISS data stream.
///
/// https://en.wikipedia.org/wiki/KISS_(amateur_radio_protocol)
#[must_use]
fn escape(bytes: &[u8]) -> Vec<u8> {
    // Add 10% capacity to leave room for escaped
    let mut ret = Vec::with_capacity((3 + bytes.len()) * 110 / 100);
    ret.push(KISS_FEND);
    ret.push(0); // TODO: port
    for &b in bytes {
        match b {
            KISS_FEND => ret.extend(vec![KISS_FESC, KISS_TFEND]),
            KISS_FESC => ret.extend(vec![KISS_FESC, KISS_TFESC]),
            b => ret.push(b),
        }
    }
    ret.push(KISS_FEND);
    ret
}

/// Find frames from a KISS stream.
///
/// Because this function only returns the index of the first frame, the frame
/// of course is not unescaped.
#[must_use]
fn find_frame(vec: &std::collections::VecDeque<u8>) -> Option<(usize, usize)> {
    let mut start_index = None;

    for (i, &value) in vec.iter().enumerate() {
        if value == KISS_FEND {
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

/// Unescape KISS data stream.
/// https://en.wikipedia.org/wiki/KISS_(amateur_radio_protocol)
#[must_use]
fn unescape(data: &[u8]) -> Vec<u8> {
    let mut unescaped = Vec::with_capacity(data.len());
    let mut is_escaped = false;
    for &byte in data {
        if is_escaped {
            unescaped.push(match byte {
                KISS_TFESC => KISS_FESC,
                KISS_TFEND => KISS_FEND,
                other => panic!("TODO: kiss unescape error: escaped {other}"),
            });
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

impl Hub for Kiss {
    fn clone(&self) -> Box<dyn Hub> {
        todo!()
    }
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        let parsed = Packet::parse(frame)?;
        debug!("Sending frame… {frame:?}: {parsed:?}");
        self.port.write_all(&escape(frame))?;
        self.port.flush()?;
        Ok(())
    }
    fn recv_timeout(&mut self, timeout: std::time::Duration) -> Result<Option<Vec<u8>>> {
        let end = std::time::Instant::now() + timeout;
        loop {
            self.port
                .set_timeout(end.saturating_duration_since(std::time::Instant::now()))?;
            let mut buf = [0u8; 1];
            let buf = match self.port.read(&mut buf) {
                Ok(n) => &buf[..n],
                Err(e) => {
                    if false {
                        debug!("TODO: Read error: {e}, assuming timeout");
                    }
                    break;
                }
            };
            //debug!("Got {} bytes from serial", buf.len());
            self.buf.extend(buf);
            while let Some((a, b)) = find_frame(&self.buf) {
                if b - a < 14 {
                    debug!("short packet {a} {b}");
                    self.buf.drain(..(a + 1));
                    continue;
                }
                let bytes: Vec<_> = self
                    .buf
                    .iter()
                    .skip(a + 2)
                    .take(b - a - 2)
                    .cloned()
                    .collect();
                self.buf.drain(..b);
                debug!("After drain: {:?}", self.buf);
                let bytes = unescape(&bytes);
                if bytes.len() > 14 {
                    debug!("Found from (not yet unescaped) from {a} to {b}: {bytes:?}");
                    match Packet::parse(&bytes) {
                        Ok(packet) => debug!("... Decoded as: {:?}", packet),
                        Err(e) => {
                            debug!("... Failed to decode: {:?}", e);
                            panic!();
                        }
                    }
                    return Ok(Some(bytes.to_vec()));
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_serial() -> Result<()> {
        // TODO: test invalid calls.
        let a = Addr::new("M0THC")?.serialize(true, false, false, false);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 97]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC");

        let a = Addr::new("M0THC-0")?.serialize(true, false, false, false);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 97]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC");

        let a = Addr::new("M0THC-1")?.serialize(true, false, false, false);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 99]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC-1");

        let a = Addr::new("M0THC-2")?.serialize(false, true, false, false);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 100 + 0x80]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC-2");

        let a = Addr::new("M0THC-3")?.serialize(false, false, true, false);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 38]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC-3");

        let a = Addr::new("M0THC-4")?.serialize(false, false, false, true);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 72]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC-4");
        Ok(())
    }

    #[test]
    fn serialize_sabm() -> Result<()> {
        let src = Addr::new("M0THC-1")?;
        let dst = Addr::new("M0THC-2")?;
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
            .serialize(false),
            vec![154, 96, 168, 144, 134, 64, 228, 154, 96, 168, 144, 134, 64, 99, 63], //, 111, 212]
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
            .serialize(false),
            vec![154, 96, 168, 144, 134, 64, 228, 154, 96, 168, 144, 134, 64, 99, 47], // , 238, 196]
        );
        Ok(())
    }
}
