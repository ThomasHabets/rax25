//! rax25 - Rust AX.25 connected more library.
//!
//! * <https://github.com/ThomasHabets/rax25>
//! * <https://blog.habets.se/2024/09/An-AX.25-implementation-in-Rust.html>
//!
//! # Status
//!
//! * Seems to work well.
//! * Both 8 and 128 modulus supported.
//! * REJ untested / probably broken.
//! * SREJ untested / mostly broken.
//! * The sync API is not great.
//! * The Async API works well as long as you only need one connection active.
//! * The parser needs some work, as Addr duplicates information part of Packet
//!   too.
//!
//! ## Interoperability tested regularly
//!
//! * Linux kernel
//! * Direwolf
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::state::Modulus;
use log::debug;

mod error;
mod fcs;
pub mod state;
pub mod xid;
pub use error::{Error, Result};
pub use state::{Experiment, NegotiatedParameters, XidConfig};

const USE_FCS: bool = false;

#[cfg(feature = "async")]
pub mod r#async;

#[cfg(feature = "serial")]
pub mod sync;

pub mod pcap;

/// Helper function for use with clap to parse command line durations.
///
/// Bare numbers are seconds. The suffixes `ms`, `s`, `m`, and `h` are also
/// accepted.
pub fn parse_duration(arg: &str) -> Result<std::time::Duration> {
    if let Some(milliseconds) = arg.strip_suffix("ms") {
        return Ok(std::time::Duration::from_millis(milliseconds.parse()?));
    }
    if let Some(seconds) = arg.strip_suffix('s') {
        return Ok(std::time::Duration::from_secs(seconds.parse()?));
    }
    if let Some(minutes) = arg.strip_suffix('m') {
        return Ok(std::time::Duration::from_mins(minutes.parse()?));
    }
    if let Some(hours) = arg.strip_suffix('h') {
        return Ok(std::time::Duration::from_hours(hours.parse()?));
    }
    Ok(std::time::Duration::from_secs(arg.parse()?))
}

/// Extra AX.25 address flags, independent of their wire encoding.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct AddrFlags(u8);

impl AddrFlags {
    /// This is the last address in the address field.
    pub const LAST: Self = Self(1);
    /// Command/response for source/destination, or repeated for a digipeater.
    pub const HIGH: Self = Self(2);
    /// Extended sequencing; encoded by clearing reserved wire bit 6.
    pub const EXTENDED: Self = Self(4);
    /// DAMA; encoded by clearing reserved wire bit 5.
    pub const DAMA: Self = Self(8);

    /// No extra flags (both reserved wire bits are set).
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Whether all the supplied flags are set.
    #[must_use]
    pub const fn contains(self, flags: Self) -> bool {
        self.0 & flags.0 == flags.0
    }

    /// Set or clear the supplied flags.
    #[must_use]
    pub const fn with(self, flags: Self, enabled: bool) -> Self {
        if enabled {
            Self(self.0 | flags.0)
        } else {
            Self(self.0 & !flags.0)
        }
    }
}

impl std::ops::BitOr for AddrFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for AddrFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

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
    flags: AddrFlags,
}

impl Addr {
    /// Create a new Addr from string. The extra bits are all clear.
    pub fn new(s: &str) -> Result<Self> {
        let s = s.to_uppercase();
        let re = regex::Regex::new(r"^[A-Z0-9]{3,6}(?:-(?:[0-9]|1[0-5]))?$")
            .expect("can't happen: Regex compile fail");
        if !re.is_match(&s) {
            return Err(Error::InvalidCallsign(s));
        }
        Ok(Self {
            t: s,
            flags: AddrFlags::empty(),
        })
    }

    /// Set the command/response or repeated bit.
    #[must_use]
    pub fn set_highbit(mut self, v: bool) -> Self {
        self.flags = self.flags.with(AddrFlags::HIGH, v);
        self
    }

    /// Set lowbit.
    #[must_use]
    pub fn set_lowbit(mut self, v: bool) -> Self {
        self.flags = self.flags.with(AddrFlags::LAST, v);
        self
    }

    /// Create a new Addr from string and the extra bits.
    pub fn new_bits(s: &str, flags: AddrFlags) -> Result<Self> {
        let mut a = Self::new(s)?;
        a.flags = flags;
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
            return Err(Error::InvalidSerializedCallsign(bytes.to_vec()));
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
            AddrFlags::empty()
                .with(AddrFlags::LAST, bytes[6] & 1 != 0)
                .with(AddrFlags::HIGH, bytes[6] & 0x80 != 0)
                .with(AddrFlags::EXTENDED, bytes[6] & 0b0100_0000 == 0)
                .with(AddrFlags::DAMA, bytes[6] & 0b0010_0000 == 0),
        )
    }

    /// Serialize the callsign and SSID, plus explicit bits.
    #[must_use]
    pub fn serialize(&self, flags: AddrFlags) -> Vec<u8> {
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
            | (if flags.contains(AddrFlags::EXTENDED) {
                0
            } else {
                0b0100_0000
            })
            | (if flags.contains(AddrFlags::DAMA) {
                0
            } else {
                0b0010_0000
            })
            | u8::from(flags.contains(AddrFlags::LAST))
            | (if flags.contains(AddrFlags::HIGH) {
                0x80
            } else {
                0
            });
        ret
    }
}

/// AX.25 packet, of all types.
///
/// Maybe this should be replaced by a protobuf.
#[derive(Clone, Debug, PartialEq)]
pub struct Packet {
    src: Addr,
    dst: Addr,
    digipeater: Vec<Addr>,
    rr_extseq: Modulus,
    command_response: bool,
    command_response_la: bool,
    rr_dist1: bool,
    #[allow(clippy::struct_field_names)]
    packet_type: PacketType,
}

/// All packet types.
#[derive(Clone, Debug, PartialEq)]
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
#[derive(Debug, PartialEq, Clone)]
pub struct Xid {
    pub poll: bool,
    pub parameters: Option<crate::xid::XidParameters>,
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
    pub nr: u8,
    pub ns: u8,
    pub poll: bool,
    pub pid: u8,
    pub payload: Vec<u8>,
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
    pub pid: u8,
    pub push: bool,
    pub payload: Vec<u8>,
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
    fn sequence_modulus(src: &Addr, ext: Option<bool>) -> Modulus {
        if ext.unwrap_or_else(|| src.flags.contains(AddrFlags::EXTENDED)) {
            Modulus::Extended
        } else {
            Modulus::Standard
        }
    }

    /// Construct an XID command or response, with an optional information field.
    #[must_use]
    pub fn xid(
        src: Addr,
        dst: Addr,
        command: bool,
        poll: bool,
        parameters: Option<xid::XidParameters>,
    ) -> Self {
        Self {
            src,
            dst,
            digipeater: vec![],
            rr_extseq: Modulus::Standard,
            command_response: command,
            command_response_la: !command,
            rr_dist1: false,
            packet_type: PacketType::Xid(Xid { poll, parameters }),
        }
    }

    /// Construct a UI frame.
    // TODO: allow setting all the other fields.
    #[must_use]
    pub fn ui<T: Into<Vec<u8>>>(src: Addr, dst: Addr, payload: T) -> Self {
        Self {
            src,
            dst,
            digipeater: vec![],
            rr_extseq: Modulus::Standard,
            command_response: false,
            command_response_la: true,
            rr_dist1: false,
            packet_type: PacketType::Ui(Ui {
                pid: 0xf0,
                push: false,
                payload: payload.into(),
            }),
        }
    }
    /// Get the packet type.
    #[must_use]
    pub fn packet_type(&self) -> &PacketType {
        &self.packet_type
    }
    /// Serialize a packet, either as standard mod-8, or extended mod-128.
    #[must_use]
    #[allow(clippy::too_many_lines)]
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
            self.dst.serialize(
                AddrFlags::empty()
                    .with(AddrFlags::HIGH, self.command_response)
                    .with(AddrFlags::EXTENDED, self.rr_dist1),
            ),
        );
        assert_ne!(self.command_response, self.command_response_la);
        ret.extend(
            self.src.serialize(
                AddrFlags::empty()
                    .with(AddrFlags::LAST, self.digipeater.is_empty())
                    .with(AddrFlags::HIGH, self.command_response_la)
                    // Setting this bit for extseq seems to be a de facto standard.
                    .with(AddrFlags::EXTENDED, self.rr_extseq.is_extended()),
            ),
        );

        {
            let l = self.digipeater.len();
            for (n, digi) in self.digipeater.iter().enumerate() {
                ret.extend(digi.serialize(AddrFlags::empty().with(AddrFlags::LAST, n == l - 1)));
            }
        }

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
                ret.push(CONTROL_DISC | if disc.poll { CONTROL_POLL } else { 0 });
            }
            PacketType::Dm(s) => ret.push(CONTROL_DM | if s.poll { CONTROL_POLL } else { 0 }),
            // TODO: FRMR data too.
            PacketType::Frmr(s) => ret.push(CONTROL_FRMR | if s.poll { CONTROL_POLL } else { 0 }),
            PacketType::Ui(s) => {
                ret.push(CONTROL_UI | if s.push { CONTROL_POLL } else { 0 });
                ret.push(s.pid);
                ret.extend(&s.payload);
            }
            PacketType::Xid(s) => {
                ret.push(CONTROL_XID | if s.poll { CONTROL_POLL } else { 0 });
                if let Some(parameters) = &s.parameters {
                    ret.extend(parameters.serialize());
                }
            }
            PacketType::Test(s) => {
                ret.push(CONTROL_TEST | if s.poll { CONTROL_POLL } else { 0 });
                ret.extend(&s.payload);
            }

            // S frames.
            PacketType::Rr(s) => {
                if ext {
                    ret.push(CONTROL_RR);
                    ret.push((s.nr << 1) & 0xFE | u8::from(s.poll));
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
                    ret.push((s.nr << 1) & 0xFE | u8::from(s.poll));
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
                    ret.push((s.nr << 1) & 0xFE | u8::from(s.poll));
                } else {
                    ret.push(CONTROL_REJ | if s.poll { CONTROL_POLL } else { 0 });
                }
            }
            PacketType::Srej(s) => {
                if ext {
                    ret.push(CONTROL_SREJ);
                    ret.push((s.nr << 1) & 0xFE | u8::from(s.poll));
                } else {
                    ret.push(CONTROL_SREJ | if s.poll { CONTROL_POLL } else { 0 });
                }
            }
            PacketType::Iframe(iframe) => {
                if ext {
                    ret.push(CONTROL_IFRAME | ((iframe.ns << 1) & 0xFE));
                    ret.push((iframe.nr << 1) & 0xFE | u8::from(iframe.poll));
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
        }
        if USE_FCS {
            let crc = fcs::fcs(&ret);
            ret.push(crc[0]);
            ret.push(crc[1]);
        }
        ret
    }

    /// Parse packet from bytes.
    ///
    /// A packet with sequence numbers in it (S and I frames) cannot be parsed
    /// without knowing if it's extended or not, because the control field is
    /// either one or two bytes.
    ///
    /// Ideally you already know, because you sent, received, or at least saw
    /// the SABM (not extended) or SABME (extended).
    ///
    /// The Linux stack uses the `rbit_ext` reserved bit in the source address
    /// to indicate extended mode. This is the used by the other Linux tooling
    /// like `axlisten`. But it's nonstandard.
    ///
    /// In theory other heuristics can be provided, to try to brute force the
    /// mode. But really, it's best if you know ahead of time.
    ///
    /// This code supports using the Linux bit, by providing `None` as `ext`, as
    /// opposed to `Some(bool)`.
    pub fn parse(bytes: &[u8], ext: Option<bool>) -> Result<Self> {
        let do_fcs = USE_FCS;
        if bytes.len() < if do_fcs { 17 } else { 15 } {
            return Err(Error::PacketTooShort {
                length: bytes.len(),
            });
        }
        // TODO: check FCS.
        let bytes = if do_fcs {
            &bytes[..(bytes.len() - 2)]
        } else {
            bytes
        };
        let dst = Addr::parse(&bytes[0..7])?;
        let src = Addr::parse(&bytes[7..14])?;

        let rr_extseq = Self::sequence_modulus(&src, ext);
        let ext = rr_extseq.is_extended();

        let mut digipeater = Vec::new();
        let mut pos = 14;
        let mut more_addresses = !src.flags.contains(AddrFlags::LAST);
        while more_addresses {
            let digi = Addr::parse(&bytes[pos..pos + 7])?;
            more_addresses = !digi.flags.contains(AddrFlags::LAST);
            pos += 7;
            digipeater.push(digi);
        }

        let rest = &bytes[pos..];
        let control1 = rest[0];
        let (poll, nr, ns, bytes) = {
            if !ext || control1 & TYPE_MASK == 3 {
                // NOTE: ns/nr will be nonsense for U frames.
                // ns will be nonsense for S frames.
                (
                    control1 & CONTROL_POLL == CONTROL_POLL,
                    (control1 >> 5) & 7,
                    (control1 >> 1) & 7,
                    &rest[1..],
                )
            } else {
                if rest.len() < 2 {
                    return Err(Error::ExtendedControlTooShort);
                }
                let control2 = rest[1];
                (
                    control2 & 1 == 1,
                    (control2 >> 1) & 127,
                    (control1 >> 1) & 127,
                    &rest[2..],
                )
            }
        };
        Ok(Packet {
            src: src.clone(),
            dst: dst.clone(),
            command_response: dst.flags.contains(AddrFlags::HIGH),
            command_response_la: src.flags.contains(AddrFlags::HIGH),
            rr_dist1: dst.flags.contains(AddrFlags::EXTENDED),
            rr_extseq,
            digipeater,
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
                    CONTROL_RR => PacketType::Rr(Rr { poll, nr }),
                    CONTROL_RNR => PacketType::Rnr(Rnr { poll, nr }),
                    CONTROL_REJ => PacketType::Rej(Rej { poll, nr }),
                    CONTROL_SREJ => PacketType::Srej(Srej { poll, nr }),
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
                        pid: bytes[0],
                        payload: bytes[1..].to_vec(),
                    }),
                    CONTROL_XID => PacketType::Xid(Xid {
                        poll,
                        parameters: (!bytes.is_empty())
                            .then(|| xid::XidParameters::parse(bytes))
                            .transpose()?,
                    }),
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
            rr_extseq: Modulus::Standard,
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
            rr_extseq: Modulus::Standard,
            digipeater: vec![],
            packet_type: PacketType::Ua(Ua { poll: true }),
        }
    }
}

#[cfg(test)]
impl Hub for FakeKiss {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        let packet = Packet::parse(frame, None)?;
        match &packet.packet_type {
            PacketType::Sabm(_) | PacketType::Sabme(_) | PacketType::Disc(_) => {
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
            .map_err(|_| Error::BroadcastFailed)?;
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
/// <https://en.wikipedia.org/wiki/KISS_(amateur_radio_protocol)>
#[cfg(feature = "serial")]
pub struct Kiss {
    buf: std::collections::VecDeque<u8>,
    port: Box<dyn serialport::SerialPort>,
}

#[cfg(feature = "serial")]
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
#[cfg(feature = "serial")]
pub struct BusKiss {
    rx: bus::BusReader<BusMessage>,
    bus: Arc<Mutex<bus::Bus<BusMessage>>>,
    kiss: Kiss,
    id: usize,
}
#[cfg(feature = "serial")]
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
            if let Ok(rx) = self.rx.recv_timeout(d)
                && rx.sender != self.id
            {
                self.kiss.send(&rx.data).unwrap();
            }
            if let Ok(Some(rx)) = self.kiss.recv_timeout(d) {
                self.bus
                    .lock()
                    .unwrap()
                    .try_broadcast(BusMessage {
                        sender: self.id,
                        data: rx,
                    })
                    .map_err(|_| Error::QueueFull)
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
/// <https://en.wikipedia.org/wiki/KISS_(amateur_radio_protocol)>
#[must_use]
pub fn escape(bytes: &[u8]) -> Vec<u8> {
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
pub(crate) fn find_frame(vec: &std::collections::VecDeque<u8>) -> Option<(usize, usize)> {
    let mut start_index = None;

    for (i, &value) in vec.iter().enumerate() {
        if value == KISS_FEND {
            if let Some(start) = start_index {
                // If start_index is already set and we find another 0xC0
                return Some((start, i));
            }
            // Set the start_index when we find the first 0xC0
            start_index = Some(i);
        }
    }

    None // Return None if no valid subrange is found
}

/// Unescape KISS data stream.
/// <https://en.wikipedia.org/wiki/KISS_(amateur_radio_protocol)>
#[must_use]
pub fn unescape(data: &[u8]) -> Vec<u8> {
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
    assert!(!is_escaped);
    unescaped
}

#[cfg(feature = "serial")]
impl Hub for Kiss {
    fn clone(&self) -> Box<dyn Hub> {
        todo!()
    }
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        let parsed = Packet::parse(frame, None)?;
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
                    self.buf.drain(..=a);
                    continue;
                }
                let bytes: Vec<_> = self
                    .buf
                    .iter()
                    .skip(a + 2)
                    .take(b - a - 2)
                    .copied()
                    .collect();
                self.buf.drain(..b);
                debug!("After drain: {:?}", self.buf);
                let bytes = unescape(&bytes);
                if bytes.len() > 14 {
                    debug!("Found from (not yet unescaped) from {a} to {b}: {bytes:?}");
                    match Packet::parse(&bytes, None) {
                        Ok(packet) => debug!("... Decoded as: {packet:?}"),
                        Err(e) => {
                            debug!("... Failed to decode: {e:?}");
                            panic!();
                        }
                    }
                    return Ok(Some(bytes));
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
    fn parse_with_digipeat() -> Result<()> {
        let bytes = &[
            130, 160, 150, 96, 96, 104, 96, 154, 96, 168, 144, 134, 64, 234, 174, 146, 136, 138,
            98, 64, 98, 174, 146, 136, 138, 100, 64, 99, 3, 240, 59, 71, 111, 111, 103, 108, 101,
            32, 32, 32, 42, 53, 49, 50, 49, 55, 53, 122, 53, 49, 51, 49, 46, 57, 57, 78, 47, 48,
            48, 48, 48, 55, 46, 53, 53, 87, 46, 71, 111, 111, 103, 108, 101, 13,
        ];
        let packet = Packet::parse(bytes, None)?;
        assert_eq!(packet.src.call(), "M0THC-5");
        assert_eq!(packet.dst.call(), "APK004");
        assert_eq!(
            packet.digipeater,
            [
                Addr {
                    t: "WIDE1-1".to_string(),
                    flags: AddrFlags::empty(),
                },
                Addr {
                    t: "WIDE2-1".to_string(),
                    flags: AddrFlags::LAST,
                },
            ]
        );
        let PacketType::Ui(ui) = packet.packet_type() else {
            panic!("Wrong type of packet {packet:?}");
        };
        assert_eq!(
            &String::from_utf8(ui.payload.clone()).expect("test payload is UTF-8"),
            ";Google   *512175z5131.99N/00007.55W.Google\r"
        );
        Ok(())
    }

    #[test]
    fn addr_serial() -> Result<()> {
        // TODO: test invalid calls.
        let a = Addr::new("M0THC")?.serialize(AddrFlags::LAST);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 97]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC");

        let a = Addr::new("M0THC-0")?.serialize(AddrFlags::LAST);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 97]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC");

        let a = Addr::new("M0THC-1")?.serialize(AddrFlags::LAST);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 99]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC-1");

        let a = Addr::new("M0THC-2")?.serialize(AddrFlags::HIGH);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 100 + 0x80]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC-2");

        let a = Addr::new("M0THC-3")?.serialize(AddrFlags::EXTENDED);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 38]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC-3");

        let a = Addr::new("M0THC-4")?.serialize(AddrFlags::DAMA);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 72]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC-4");
        Ok(())
    }

    #[test]
    fn addr_flags_all_wire_combinations() -> Result<()> {
        assert_eq!(std::mem::size_of::<AddrFlags>(), 1);
        assert_eq!(AddrFlags::default(), AddrFlags::empty());
        // Indexed by LAST, HIGH, EXTENDED, DAMA; reserved bits are active-low.
        let wire_bits = [
            0x60, 0x61, 0xe0, 0xe1, 0x20, 0x21, 0xa0, 0xa1, 0x40, 0x41, 0xc0, 0xc1, 0x00, 0x01,
            0x80, 0x81,
        ];
        for (combination, wire) in wire_bits.into_iter().enumerate() {
            let mut flags = AddrFlags::empty();
            for (index, flag) in [
                AddrFlags::LAST,
                AddrFlags::HIGH,
                AddrFlags::EXTENDED,
                AddrFlags::DAMA,
            ]
            .into_iter()
            .enumerate()
            {
                let enabled = combination & (1 << index) != 0;
                if enabled {
                    flags |= flag;
                }
                assert_eq!(flags.contains(flag), enabled);
            }
            for ssid in 0..16 {
                let call = if ssid == 0 {
                    "M0THC".to_string()
                } else {
                    format!("M0THC-{ssid}")
                };
                let addr = Addr::new_bits(&call, flags)?;
                let expected = vec![154, 96, 168, 144, 134, 64, wire | (ssid << 1)];
                assert_eq!(addr.serialize(flags), expected);
                let parsed = Addr::parse(&expected)?;
                assert_eq!(parsed, addr);
                assert_eq!(parsed.flags, flags);
                assert_eq!(parsed.serialize(parsed.flags), expected);
                // Explicit serialization flags override the stored flags.
                assert_eq!(addr.serialize(AddrFlags::empty())[6], 0x60 | (ssid << 1));
            }
        }
        Ok(())
    }

    #[test]
    fn addr_flag_setters_preserve_other_flags() -> Result<()> {
        let reserved = AddrFlags::EXTENDED | AddrFlags::DAMA;
        let addr = Addr::new_bits("M0THC", reserved)?
            .set_highbit(true)
            .set_lowbit(true);
        assert_eq!(addr.flags, reserved | AddrFlags::HIGH | AddrFlags::LAST);
        assert_eq!(
            addr.clone().set_highbit(false).flags,
            reserved | AddrFlags::LAST
        );
        assert_eq!(
            addr.clone().set_lowbit(false).flags,
            reserved | AddrFlags::HIGH
        );
        assert_eq!(addr.set_highbit(false).set_lowbit(false).flags, reserved);
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
                rr_extseq: Modulus::Standard,
                digipeater: vec![],
                packet_type: PacketType::Sabm(Sabm { poll: true })
            }
            .serialize(false),
            vec![
                154, 96, 168, 144, 134, 64, 228, // dst
                154, 96, 168, 144, 134, 64, 99, // src
                63
            ], //, 111, 212]
        );
        assert_eq!(
            Packet {
                command_response: true,
                command_response_la: false,
                digipeater: vec![],
                rr_dist1: false,
                rr_extseq: Modulus::Standard,
                src,
                dst,
                packet_type: PacketType::Sabm(Sabm { poll: false })
            }
            .serialize(false),
            vec![
                154, 96, 168, 144, 134, 64, 228, 154, 96, 168, 144, 134, 64, 99, 47
            ], // , 238, 196]
        );
        Ok(())
    }

    #[test]
    fn serialize_ui_repeat() -> Result<()> {
        let src = Addr::new("M0THC-1")?;
        let dst = Addr::new("M0THC-2")?.set_highbit(true);
        let packet = Packet {
            src: src.clone(),
            dst: dst.clone(),
            command_response: true,
            command_response_la: false,
            rr_dist1: false,
            rr_extseq: Modulus::Standard,
            digipeater: vec![
                Addr::new("WIDE1-1")?,
                Addr::new("WIDE2-2")?.set_lowbit(true),
            ],
            packet_type: PacketType::Ui(Ui {
                pid: 0xF0,
                push: false,
                payload: "yo".into(),
            }),
        };
        let got = packet.serialize(false);
        assert_eq!(
            got,
            vec![
                154, 96, 168, 144, 134, 64, 228, // dst
                154, 96, 168, 144, 134, 64, 98, // src
                174, 146, 136, 138, 98, 64, 98, // rpt1
                174, 146, 136, 138, 100, 64, 101, //rpt2
                3,   // UI
                240, // Pid
                121, 111 // Yo
            ],
        );
        let parsed = Packet::parse(&got, None)?;
        assert_eq!(packet, parsed);
        Ok(())
    }
}
