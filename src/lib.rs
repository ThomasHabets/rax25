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
//!
//! ## Interoperability tested regularly
//!
//! * Linux kernel (removed in newer kernels)
//! * Direwolf
#![allow(clippy::missing_errors_doc)]
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use log::debug;

use crate::state::Modulus;

mod error;
mod fcs;
pub mod state;
pub mod xid;
pub use error::{Error, Result};
pub use state::{Experiment, NegotiatedParameters, XidConfig};

/// We assume that the KISS modem attaches the checksum on TX and checks &
/// removes it on RX.
///
/// In general it's better if the modem does this, as even for regular Bell 202
/// it'll have some access to soft bits for doing smarter correction. And rax25
/// would work with a smarter RF interface that uses something better than a
/// regular old FCS.
const USE_FCS: bool = false;

#[cfg(feature = "async")]
pub mod r#async;

#[cfg(feature = "serial")]
pub mod sync;

pub mod pcap;

#[cfg(feature = "async")]
pub mod engine;

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
///
/// The AX.25 encoding of an address doesn't need 8 bits per callsign character,
/// and uses the extra bits to encode extra information. The semantic value of
/// some of these fields depends on in what context they are used.
///
/// Spec:
/// * 1984: 2.2.13 on page 5 onwards.
/// * 1998: 3.12 on page 9 onwards.
/// * 2006: 3.12 on page 17 onwards.
/// * 2017: 3.12 on page 18 onwards.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct AddrFlags(u8);

impl AddrFlags {
    /// This is the last address in the address field. It's set for the source
    /// address if there are no digipeaters, or on the last digipeater if there
    /// are digipeaters.
    pub const LAST: Self = Self(1);
    /// Command/response for source/destination, or repeated for a digipeater.
    pub const HIGH: Self = Self(2);
    /// Extended sequencing; encoded by clearing reserved wire bit 6.
    ///
    /// This bit is reserved, but used by the now deprecated Linux stack in the
    /// source address field to signify mod-128 extended sequencing.
    ///
    /// Reserved bits are set to 1, so enabling `EXTENDED` makes the bit in the
    /// packet 0.
    ///
    /// Rax25 sets this bit appropriately in order to help the `axlisten`
    /// command parse the packet correctly, but internally tracks the connection
    /// meaning the remote end does not need to follow this convention.
    pub const EXTENDED: Self = Self(4);
    /// DAMA; encoded by clearing reserved wire bit 5.
    ///
    /// This bit is reserved, but used by the Linux stack in the source
    /// address's SSID octet to indicate Demand Assigned Multiple Access
    /// (DAMA). It is active-low: clear indicates DAMA, set indicates normal
    /// operation. DAMA uses a master to control when slaves may transmit.
    /// Rax25 parses and serializes this flag but does not implement DAMA
    /// polling or channel access.
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

/// Station identity: a validated callsign and SSID, without frame flags.
///
/// Callsigns are uppercase, and an explicit SSID of zero is omitted, so
/// `M0THC` and `m0thc-0` identify the same station.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Callsign(String);

impl Callsign {
    /// Parse and canonicalize a station identity.
    pub fn new(s: impl Into<String>) -> Result<Self> {
        let mut s = s.into();
        s.make_ascii_uppercase();

        let (call, valid_ssid) = match s.split_once('-') {
            Some((call, ssid)) => (
                call,
                matches!(ssid.as_bytes(), [b'0'..=b'9'] | [b'1', b'0'..=b'5']),
            ),
            None => (s.as_str(), true),
        };
        if !(3..=6).contains(&call.len())
            || !call.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || !valid_ssid
        {
            return Err(Error::InvalidCallsign(s));
        }
        if let Some(trimmed) = s.strip_suffix("-0") {
            s.truncate(trimmed.len());
        }
        Ok(Self(s))
    }

    /// Canonical callsign and SSID as text.
    #[must_use]
    pub fn call(&self) -> &str {
        &self.0
    }

    /// Attach frame-specific flags to this station identity.
    #[must_use]
    pub fn with_flags(self, flags: AddrFlags) -> Addr {
        Addr {
            callsign: self,
            flags,
        }
    }
}

impl std::fmt::Display for Callsign {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.call())
    }
}

impl std::str::FromStr for Callsign {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl From<Callsign> for Addr {
    fn from(callsign: Callsign) -> Self {
        callsign.with_flags(AddrFlags::empty())
    }
}

/// AX.25 wire address: a station identity and frame-specific flags.
///
/// The encoding for an AX.25 address includes some extra bits, so they're
/// included here. That way they can be serialized and parsed fully in and
/// out of the struct.
///
/// Spec:
/// * 1984: 2.2.13 on page 5 onwards.
/// * 1998: 3.12 on page 9 onwards.
/// * 2006: 3.12 on page 17 onwards.
/// * 2017: 3.12 on page 18 onwards.
#[derive(Debug, Clone, PartialEq)]
pub struct Addr {
    callsign: Callsign,
    flags: AddrFlags,
}

impl Addr {
    /// Create a new Addr from string. The extra bits are all clear.
    pub fn new(s: impl Into<String>) -> Result<Self> {
        Ok(Callsign::new(s)?.into())
    }

    /// Return this address with the command/response or repeated bit set to `v`.
    #[must_use]
    pub fn with_highbit(mut self, v: bool) -> Self {
        self.flags = self.flags.with(AddrFlags::HIGH, v);
        self
    }

    /// Return this address with the last-address bit set to `v`.
    ///
    /// This bit is used in the spec to signify the last address in a list of
    /// addresses. I.e. the source address for no-digipeater packets, or the
    /// last digipeater if packet has digipeaters.
    #[must_use]
    pub fn with_lowbit(mut self, v: bool) -> Self {
        self.flags = self.flags.with(AddrFlags::LAST, v);
        self
    }

    /// Create a new Addr from string and the extra bits.
    pub fn new_bits(s: impl Into<String>, flags: AddrFlags) -> Result<Self> {
        let mut a = Self::new(s)?;
        a.flags = flags;
        Ok(a)
    }

    /// Get just the callsign & SSID as a string, not the extra bits.
    #[must_use]
    pub fn call(&self) -> &str {
        self.callsign.call()
    }

    /// Station identity, excluding all frame-specific flags.
    #[must_use]
    pub fn callsign(&self) -> &Callsign {
        &self.callsign
    }

    /// Parse the callsign and the extra bits from the packet format.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 7 || bytes[..6].iter().any(|byte| byte & 1 != 0) {
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
            call,
            AddrFlags::empty()
                .with(AddrFlags::LAST, bytes[6] & 1 != 0)
                .with(AddrFlags::HIGH, bytes[6] & 0x80 != 0)
                .with(AddrFlags::EXTENDED, bytes[6] & 0b0100_0000 == 0)
                .with(AddrFlags::DAMA, bytes[6] & 0b0010_0000 == 0),
        )
    }

    /// Serialize the callsign, SSID, and stored address flags.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        self.serialize_with_flags(self.flags)
    }

    /// Serialize with explicit flags instead of the stored address flags.
    ///
    /// This does not change the flags stored in this address.
    #[must_use]
    pub fn serialize_with_flags(&self, flags: AddrFlags) -> Vec<u8> {
        let mut ret = vec![b' ' << 1; 7];
        for (i, ch) in self.call().chars().take(6).enumerate() {
            if ch == '-' {
                break;
            }
            ret[i] = (ch as u8) << 1;
        }
        let ssid = {
            let s: Vec<_> = self.call().split('-').collect();
            if s.len() == 1 {
                0
            } else {
                #[expect(
                    clippy::missing_panics_doc,
                    reason = "SSID is validated by Callsign construction"
                )]
                {
                    let ssid = s[1].parse::<u8>().unwrap();
                    assert!(ssid < 16, "ssid has impossible value {ssid}");
                    ssid
                }
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
    /// Effective sequencing mode, which may override the nonstandard
    /// `AddrFlags::EXTENDED` wire hint retained in the source address.
    modulus: Modulus,
    #[allow(clippy::struct_field_names)]
    packet_type: PacketType,
}

/// Command or response role for a v2.x frame.
///
/// Raw source and destination C bits remain independently available on
/// packets, including legacy equal-bit encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandResponse {
    Command,
    Response,
}

impl CommandResponse {
    /// Whether this frame is a command.
    #[must_use]
    pub fn is_command(self) -> bool {
        self == Self::Command
    }

    /// Whether this frame is a response.
    #[must_use]
    pub fn is_response(self) -> bool {
        self == Self::Response
    }
}

impl From<bool> for CommandResponse {
    /// Interpret a destination C bit using v2.x command/response encoding.
    fn from(command: bool) -> Self {
        if command {
            Self::Command
        } else {
            Self::Response
        }
    }
}

/// Value of the poll/final bit.
///
/// A set bit means Poll in a command and Final in a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollFinal {
    Clear,
    Set,
}

impl PollFinal {
    /// Whether the poll/final bit is set.
    #[must_use]
    pub fn is_set(self) -> bool {
        self == Self::Set
    }
}

impl From<bool> for PollFinal {
    fn from(set: bool) -> Self {
        if set { Self::Set } else { Self::Clear }
    }
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
    poll: PollFinal,
}

/// SAMBE - Set Asynchronous Balanced Mode Extended (4.3.3.2, page 23)
#[derive(Clone, Debug, PartialEq)]
pub struct Sabme {
    poll: PollFinal,
}

/// RR - Receiver Ready (4.3.2.1, page 21)
///
/// Basically an ACK.
#[derive(Debug, PartialEq, Clone)]
pub struct Rr {
    poll: PollFinal,
    nr: u8,
}

/// REJ - Reject (4.3.2.3, page 21)
///
/// Unclear why this is even needed. Couldn't RR with NR older than last sent
/// be equally eager to retransmit?
#[derive(Debug, PartialEq, Clone)]
pub struct Rej {
    poll: PollFinal,
    nr: u8,
}

/// SREJ - Selective reject (4.3.2.4, page 21)
///
/// Request retransmissions of a single iframe.
#[derive(Debug, PartialEq, Clone)]
pub struct Srej {
    poll: PollFinal,
    nr: u8,
}

/// FRMR - A deprecated error signaling (4.3.3.9, page 28)
///
/// The AX.25 2.2 spec deprecates this, and says to not generate these frames. But
/// it does specify what to do when receiving one.
#[derive(Debug, PartialEq, Clone)]
pub struct Frmr {
    poll: PollFinal,
}

/// Test - Test frame
///
/// * 1984: n/a
/// * 1998: 4.3.3.8, page 28
/// * 2006: 4.3.3.8, page 32
/// * 2017: 4.3.3.8, page 35
///
/// It's ping, basically. The payload is mirrored back, or (if there's not
/// enough room to store the payload), an empty response is returned.
///
/// The intended use of the poll flag here is unclear.
#[derive(Debug, PartialEq, Clone)]
pub struct Test {
    poll: PollFinal,
    payload: Vec<u8>,
}

/// XID - Exchange Identification (4.3.3.7, page 24)
///
/// ISO 8885 exchange of capabilities, like extended sequence numbers,
/// max IFRAME size ("MTU"), and lots of other stuff.
#[derive(Debug, PartialEq, Clone)]
pub struct Xid {
    pub poll: PollFinal,
    pub parameters: Option<crate::xid::XidParameters>,
}

/// RNR - Receiver Not Ready (4.3.2.2, page 21)
///
/// Like RR, but asks the sender to not send more data for now.
/// The TCP version of this would be a closed receiver window.
#[derive(Debug, PartialEq, Clone)]
pub struct Rnr {
    poll: PollFinal,
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
    poll: PollFinal,
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
    pub poll: PollFinal,
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
    pub push: PollFinal,
    pub payload: Vec<u8>,
}

/// DM - Disconnected Mode
///
/// * 1998: 4.3.3.5, page 23
///
/// Sent as reply to SAMB(E) if a connection can't be established, or as a reply
/// to connection-assuming frames when no connection is in fact active.
///
/// Basically a TCP RST.
#[derive(Clone, Debug, PartialEq)]
pub struct Dm {
    poll: PollFinal,
}

/// DISC - Disconnect
///
/// * 1998: 4.3.3.3, page 23
///
/// End the connection. A DISC is acked with a UA packet, which seems
/// silly. Replying with DISC would make more sense, but hey ho.
#[derive(Clone, Debug, PartialEq)]
pub struct Disc {
    poll: PollFinal,
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
    /// Select the sequencing mode for control-field encoding and the
    /// nonstandard source-address extended-mode hint, when enabled.
    #[must_use]
    pub fn with_extended(mut self, extended: bool) -> Self {
        self.modulus = if extended {
            Modulus::Extended
        } else {
            Modulus::Standard
        };
        self
    }

    /// Destination C bit: true for a v2.x command, false for a response.
    /// Legacy frames may have equal source and destination C bits.
    #[must_use]
    pub fn command_response(&self) -> bool {
        self.dst.flags.contains(AddrFlags::HIGH)
    }

    /// Source C bit: true for a v2.x response, false for a command.
    /// Legacy frames may have equal source and destination C bits.
    #[must_use]
    pub fn command_response_src(&self) -> bool {
        self.src.flags.contains(AddrFlags::HIGH)
    }

    /// Set both address C bits for a v2.x command or response.
    pub fn set_command_response(&mut self, command: CommandResponse) {
        self.dst.flags = self.dst.flags.with(AddrFlags::HIGH, command.is_command());
        self.src.flags = self.src.flags.with(AddrFlags::HIGH, command.is_response());
    }

    fn sequence_modulus(src: &Addr, ext: Option<bool>) -> Modulus {
        if ext.unwrap_or_else(|| src.flags.contains(AddrFlags::EXTENDED)) {
            Modulus::Extended
        } else {
            Modulus::Standard
        }
    }

    /// Construct an XID command or response, with an optional information field.
    ///
    /// ```
    /// use rax25::{Callsign, CommandResponse, Packet, PollFinal};
    /// let query = Packet::xid(
    ///     Callsign::new("LOCAL")?, Callsign::new("REMOTE")?,
    ///     CommandResponse::Command, PollFinal::Set, None,
    /// );
    /// # Ok::<(), rax25::Error>(())
    /// ```
    #[must_use]
    pub fn xid(
        src: impl Into<Addr>,
        dst: impl Into<Addr>,
        command: CommandResponse,
        poll: PollFinal,
        parameters: Option<xid::XidParameters>,
    ) -> Self {
        Self {
            src: src.into().with_highbit(command.is_response()),
            dst: dst.into().with_highbit(command.is_command()),
            digipeater: vec![],
            modulus: Modulus::Standard,
            packet_type: PacketType::Xid(Xid { poll, parameters }),
        }
    }

    /// Construct a UI frame.
    // TODO: allow setting all the other fields.
    #[must_use]
    pub fn ui<T: Into<Vec<u8>>>(src: impl Into<Addr>, dst: impl Into<Addr>, payload: T) -> Self {
        Self {
            src: src.into().with_highbit(true),
            dst: dst.into().with_highbit(false),
            digipeater: vec![],
            modulus: Modulus::Standard,
            packet_type: PacketType::Ui(Ui {
                pid: 0xf0,
                push: PollFinal::Clear,
                payload: payload.into(),
            }),
        }
    }
    /// Get the packet type.
    #[must_use]
    pub fn packet_type(&self) -> &PacketType {
        &self.packet_type
    }
    /// Serialize using this packet's sequencing mode, with the Linux hint enabled.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        self.serialize_with_linux_extended_hint(true)
    }

    /// Serialize with optional Linux extended-sequencing signalling.
    ///
    /// When disabled, the reserved source-address bit remains one even in
    /// modulo-128 mode. This does not change control-field encoding, destination
    /// flags, or receive parsing; receivers must know the connection mode.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn serialize_with_linux_extended_hint(&self, enabled: bool) -> Vec<u8> {
        let ext = self.modulus.is_extended();
        let mut ret = Vec::with_capacity(
            14 + 2
                + if let PacketType::Iframe(s) = &self.packet_type {
                    s.payload.len() + 1
                } else {
                    0
                },
        );
        ret.extend(
            self.dst.serialize_with_flags(
                AddrFlags::empty()
                    .with(AddrFlags::HIGH, self.command_response())
                    .with(
                        AddrFlags::EXTENDED,
                        self.dst.flags.contains(AddrFlags::EXTENDED),
                    ),
            ),
        );
        ret.extend(
            self.src.serialize_with_flags(
                AddrFlags::empty()
                    .with(AddrFlags::LAST, self.digipeater.is_empty())
                    .with(AddrFlags::HIGH, self.command_response_src())
                    .with(AddrFlags::EXTENDED, enabled && ext),
            ),
        );

        {
            let l = self.digipeater.len();
            for (n, digi) in self.digipeater.iter().enumerate() {
                ret.extend(digi.serialize_with_flags(digi.flags.with(AddrFlags::LAST, n == l - 1)));
            }
        }

        match &self.packet_type {
            // U frames. Control always one byte.
            PacketType::Sabm(s) => {
                if ext {
                    ret.push(CONTROL_SABME | if s.poll.is_set() { CONTROL_POLL } else { 0 });
                } else {
                    ret.push(CONTROL_SABM | if s.poll.is_set() { CONTROL_POLL } else { 0 });
                }
            }
            PacketType::Sabme(s) => {
                ret.push(CONTROL_SABME | if s.poll.is_set() { CONTROL_POLL } else { 0 });
            }
            PacketType::Ua(s) => {
                ret.push(CONTROL_UA | if s.poll.is_set() { CONTROL_POLL } else { 0 });
            }
            PacketType::Disc(disc) => {
                ret.push(CONTROL_DISC | if disc.poll.is_set() { CONTROL_POLL } else { 0 });
            }
            PacketType::Dm(s) => {
                ret.push(CONTROL_DM | if s.poll.is_set() { CONTROL_POLL } else { 0 });
            }
            // TODO: FRMR data too.
            PacketType::Frmr(s) => {
                ret.push(CONTROL_FRMR | if s.poll.is_set() { CONTROL_POLL } else { 0 });
            }
            PacketType::Ui(s) => {
                ret.push(CONTROL_UI | if s.push.is_set() { CONTROL_POLL } else { 0 });
                ret.push(s.pid);
                ret.extend(&s.payload);
            }
            PacketType::Xid(s) => {
                ret.push(CONTROL_XID | if s.poll.is_set() { CONTROL_POLL } else { 0 });
                if let Some(parameters) = &s.parameters {
                    ret.extend(parameters.serialize());
                }
            }
            PacketType::Test(s) => {
                ret.push(CONTROL_TEST | if s.poll.is_set() { CONTROL_POLL } else { 0 });
                ret.extend(&s.payload);
            }

            // S frames.
            PacketType::Rr(s) => {
                if ext {
                    ret.push(CONTROL_RR);
                    ret.push((s.nr << 1) & 0xFE | u8::from(s.poll.is_set()));
                } else {
                    ret.push(
                        CONTROL_RR
                            | if s.poll.is_set() { CONTROL_POLL } else { 0 }
                            | ((s.nr << 5) & NR_MASK),
                    );
                }
            }
            PacketType::Rnr(s) => {
                if ext {
                    ret.push(CONTROL_RNR);
                    ret.push((s.nr << 1) & 0xFE | u8::from(s.poll.is_set()));
                } else {
                    ret.push(
                        CONTROL_RNR
                            | if s.poll.is_set() { CONTROL_POLL } else { 0 }
                            | ((s.nr << 5) & NR_MASK),
                    );
                }
            }
            PacketType::Rej(s) => {
                if ext {
                    ret.push(CONTROL_REJ);
                    ret.push((s.nr << 1) & 0xFE | u8::from(s.poll.is_set()));
                } else {
                    ret.push(CONTROL_REJ | if s.poll.is_set() { CONTROL_POLL } else { 0 });
                }
            }
            PacketType::Srej(s) => {
                if ext {
                    ret.push(CONTROL_SREJ);
                    ret.push((s.nr << 1) & 0xFE | u8::from(s.poll.is_set()));
                } else {
                    ret.push(CONTROL_SREJ | if s.poll.is_set() { CONTROL_POLL } else { 0 });
                }
            }
            PacketType::Iframe(iframe) => {
                if ext {
                    ret.push(CONTROL_IFRAME | ((iframe.ns << 1) & 0xFE));
                    ret.push((iframe.nr << 1) & 0xFE | u8::from(iframe.poll.is_set()));
                } else {
                    ret.push(
                        CONTROL_IFRAME
                            | if iframe.poll.is_set() {
                                CONTROL_POLL
                            } else {
                                0
                            }
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
    #[allow(clippy::too_many_lines)]
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

        let modulus = Self::sequence_modulus(&src, ext);
        let ext = modulus.is_extended();

        let mut digipeater = Vec::new();
        let mut pos = 14;
        let mut more_addresses = !src.flags.contains(AddrFlags::LAST);
        while more_addresses {
            let address = bytes.get(pos..pos + 7).ok_or(Error::PacketTooShort {
                length: bytes.len(),
            })?;
            let digi = Addr::parse(address)?;
            more_addresses = !digi.flags.contains(AddrFlags::LAST);
            pos += 7;
            digipeater.push(digi);
        }

        let rest = &bytes[pos..];
        let control1 = *rest.first().ok_or(Error::PacketTooShort {
            length: bytes.len(),
        })?;
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
        let poll = PollFinal::from(poll);
        Ok(Packet {
            src: src.clone(),
            dst: dst.clone(),
            modulus,
            digipeater,
            packet_type: match control1 & TYPE_MASK {
                // I frames. Second control byte, with NR and NS.
                // TODO: confirm pid is NO_L3
                0 | 2 => PacketType::Iframe(Iframe {
                    ns,
                    nr,
                    poll,
                    pid: NO_L3,
                    payload: bytes
                        .get(1..)
                        .ok_or(Error::PacketTooShort { length: rest.len() })?
                        .to_vec(),
                }),
                // S frames. Second control byte, with NR.
                1 => match control1 & !NR_MASK & !CONTROL_POLL {
                    CONTROL_RR => PacketType::Rr(Rr { poll, nr }),
                    CONTROL_RNR => PacketType::Rnr(Rnr { poll, nr }),
                    CONTROL_REJ => PacketType::Rej(Rej { poll, nr }),
                    CONTROL_SREJ => PacketType::Srej(Srej { poll, nr }),
                    _ => {
                        return Err(Error::Impossible(format!(
                            "Impossible logic error: {control1} failed to be supervisor"
                        )));
                    }
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
                    c => return Err(Error::UnsupportedControl(c)),
                },
                _ => {
                    return Err(Error::Impossible(format!(
                        "Logic error: {control1} & 3 > 3"
                    )));
                }
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
    fn clone(&self) -> Result<Box<dyn Hub>>;
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
            src: src.with_highbit(false),
            dst: dst.with_highbit(true),
            modulus: Modulus::Standard,
            digipeater: vec![],
            packet_type: PacketType::Iframe(Iframe {
                nr: 0,
                pid: 0xF0,
                ns: 0,
                poll: PollFinal::Set, // TODO: poll or no?
                payload,
            }),
        }
    }

    #[must_use]
    fn make_ua(src: Addr, dst: Addr) -> Packet {
        Packet {
            src: src.with_highbit(false),
            dst: dst.with_highbit(true),
            modulus: Modulus::Standard,
            digipeater: vec![],
            packet_type: PacketType::Ua(Ua {
                poll: PollFinal::Set,
            }),
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
                    Self::make_ua(packet.dst.clone(), packet.src.clone())
                        .with_extended(self.ext)
                        .serialize(),
                );
            }
            PacketType::Iframe(_) => {
                self.queue.push_back(
                    Self::make_iframe(packet.dst.clone(), packet.src.clone(), vec![3, 2, 1])
                        .with_extended(self.ext)
                        .serialize(),
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
    fn clone(&self) -> Result<Box<dyn Hub>> {
        Ok(Box::new(FakeKiss::default()))
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

fn broadcast_to_bus(bus: &Mutex<bus::Bus<BusMessage>>, message: BusMessage) -> Result<()> {
    bus.lock()
        .map_err(|_| Error::MutexPoisoned)?
        .try_broadcast(message)
        .map_err(|_| Error::QueueFull)
}

impl BusHub {
    pub fn new(bus: Arc<Mutex<bus::Bus<BusMessage>>>) -> Result<Self> {
        let rx = bus.lock().map_err(|_| Error::MutexPoisoned)?.add_rx();
        Ok(Self { rx, bus })
    }
}

impl Hub for BusHub {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        self.bus
            .lock()
            .map_err(|_| Error::MutexPoisoned)?
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

    fn clone(&self) -> Result<Box<dyn Hub>> {
        Ok(Box::new(Self::new(self.bus.clone())?))
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
        let rx = bus.lock().map_err(|_| Error::MutexPoisoned)?.add_rx();
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
                && let Err(e) = self.kiss.send(&rx.data)
            {
                log::warn!("Sending to KISS failed: {e}");
                break;
            }
            if let Ok(Some(rx)) = self.kiss.recv_timeout(d)
                && let Err(e) = broadcast_to_bus(
                    &self.bus,
                    BusMessage {
                        sender: self.id,
                        data: rx,
                    },
                )
            {
                log::warn!("Failed to broadcast: {e}");
                break;
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
pub fn unescape(data: &[u8]) -> Result<Vec<u8>> {
    let mut unescaped = Vec::with_capacity(data.len());
    let mut is_escaped = false;
    for &byte in data {
        if is_escaped {
            unescaped.push(match byte {
                KISS_TFESC => KISS_FESC,
                KISS_TFEND => KISS_FEND,
                other => return Err(Error::Kiss(format!("escaped {other}"))),
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
    if is_escaped {
        return Err(Error::Kiss("frame ends on escape state".to_string()));
    }
    Ok(unescaped)
}

#[cfg(feature = "serial")]
impl Hub for Kiss {
    fn clone(&self) -> Result<Box<dyn Hub>> {
        Err(Error::Kiss(
            "serial KISS interfaces cannot be cloned; use BusHub".to_string(),
        ))
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
                let bytes = unescape(&bytes)?;
                if bytes.len() > 14 {
                    debug!("Found from (not yet unescaped) from {a} to {b}: {bytes:?}");
                    let packet = Packet::parse(&bytes, None)?;
                    debug!("... Decoded as: {packet:?}");
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
    fn kiss_unescape_reports_malformed_sequences() -> Result<()> {
        assert!(matches!(unescape(&[KISS_FESC]), Err(Error::Kiss(_))));
        assert!(matches!(unescape(&[KISS_FESC, 0]), Err(Error::Kiss(_))));
        let payload: Vec<u8> = (0..=255).collect();
        let frame = escape(&payload);
        assert_eq!(unescape(&frame[2..frame.len() - 1])?, payload);
        assert_eq!(unescape(&[])?, []);
        Ok(())
    }

    #[test]
    fn bus_errors_preserve_queue_and_poison_failures() -> Result<()> {
        let bus = Arc::new(Mutex::new(bus::Bus::new(1)));
        let mut hub = BusHub::new(bus.clone())?;
        broadcast_to_bus(
            &bus,
            BusMessage {
                sender: 1,
                data: vec![1],
            },
        )?;
        assert!(matches!(
            broadcast_to_bus(
                &bus,
                BusMessage {
                    sender: 1,
                    data: vec![2]
                }
            ),
            Err(Error::QueueFull)
        ));
        assert!(matches!(hub.send(&[3]), Err(Error::BroadcastFailed)));
        assert_eq!(hub.recv_timeout(std::time::Duration::ZERO)?, Some(vec![1]));
        let poisoned = bus.clone();
        assert!(
            std::thread::spawn(move || {
                let _guard = poisoned.lock().unwrap();
                panic!("poison test bus");
            })
            .join()
            .is_err()
        );
        assert!(matches!(
            BusHub::new(bus.clone()),
            Err(Error::MutexPoisoned)
        ));
        assert!(matches!(Hub::clone(&hub), Err(Error::MutexPoisoned)));
        assert!(matches!(hub.send(&[4]), Err(Error::MutexPoisoned)));
        assert!(matches!(
            broadcast_to_bus(
                &bus,
                BusMessage {
                    sender: 1,
                    data: vec![]
                }
            ),
            Err(Error::MutexPoisoned)
        ));
        Ok(())
    }

    #[test]
    fn packet_parse_rejects_truncation_and_unknown_control() -> Result<()> {
        let packet = Packet::ui(Callsign::new("LOCAL")?, Callsign::new("REMOTE")?, []);
        let mut bytes = packet.serialize();
        bytes[14] = 0xff;
        assert!(matches!(
            Packet::parse(&bytes, None),
            Err(Error::UnsupportedControl(_))
        ));
        bytes.truncate(15);
        bytes[14] = 0;
        assert!(matches!(
            Packet::parse(&bytes, None),
            Err(Error::PacketTooShort { .. })
        ));
        bytes[13] &= !1;
        assert!(matches!(
            Packet::parse(&bytes, None),
            Err(Error::PacketTooShort { .. })
        ));
        bytes.truncate(14);
        bytes.extend(Addr::new("DIGI")?.with_lowbit(true).serialize());
        assert!(matches!(
            Packet::parse(&bytes, None),
            Err(Error::PacketTooShort { .. })
        ));
        Ok(())
    }

    #[test]
    fn frame_role_and_poll_final_bit_conversions() {
        for bit in [false, true] {
            let role = CommandResponse::from(bit);
            assert_eq!(role.is_command(), bit);
            assert_eq!(role.is_response(), !bit);
            assert_eq!(PollFinal::from(bit).is_set(), bit);
        }
    }

    #[test]
    fn callsign_validation_boundaries() {
        for length in 0..=8 {
            let call = "A".repeat(length);
            assert_eq!(Callsign::new(&call).is_ok(), (3..=6).contains(&length));
        }
        for byte in 0..=127_u8 {
            let call = format!("A{}0", char::from(byte));
            assert_eq!(Callsign::new(&call).is_ok(), byte.is_ascii_alphanumeric());
        }
        for invalid in [
            "ABC-", "ABC--1", "ABC-+1", "ABC-1-0", "ABC- 1", "ABC-1\n", "AB\u{e9}", "a\u{df}",
        ] {
            assert!(matches!(
                Callsign::new(invalid),
                Err(Error::InvalidCallsign(_))
            ));
        }
    }

    #[test]
    fn callsign_ssid_validation() -> Result<()> {
        for ssid in 0..=255 {
            let call = format!("ABC-{ssid}");
            let parsed = Callsign::new(&call);
            if ssid <= 15 {
                let parsed = parsed?;
                assert_eq!(parsed.call(), if ssid == 0 { "ABC" } else { &call });
            } else {
                assert!(matches!(parsed, Err(Error::InvalidCallsign(value)) if value == call));
            }
            let padded = format!("ABC-{ssid:02}");
            assert_eq!(Callsign::new(&padded).is_ok(), (10..=15).contains(&ssid));
        }
        Ok(())
    }

    #[test]
    fn callsign_identity_is_canonical_and_hashable() -> Result<()> {
        let call = Callsign::new("m0thc-0")?;
        assert_eq!(call, Callsign::new("M0THC")?);
        assert_eq!(call.call(), "M0THC");
        assert_eq!(call.to_string(), "M0THC");
        assert_eq!("m0thc-0".parse::<Callsign>()?, call);
        assert_ne!(call, Callsign::new("M0THC-1")?);
        let identities = std::collections::HashSet::from([
            call,
            Callsign::new("M0THC")?,
            Callsign::new("M0THC-1")?,
        ]);
        assert_eq!(identities.len(), 2);
        for invalid in ["", "AB", "ABCDEFG", "M0THC-16", "M0THC-00", "M0THC!"] {
            assert!(matches!(
                Callsign::new(invalid),
                Err(Error::InvalidCallsign(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn wire_addresses_keep_flags_separate_from_identity() -> Result<()> {
        let call = Callsign::new("M0THC-0")?;
        let plain = Addr::from(call.clone());
        let flags = AddrFlags::HIGH | AddrFlags::LAST | AddrFlags::EXTENDED | AddrFlags::DAMA;
        let flagged = call.clone().with_flags(flags);
        assert_eq!(plain.callsign(), &call);
        assert_eq!(flagged.callsign(), &call);
        assert_ne!(plain, flagged);
        assert_eq!(plain.flags, AddrFlags::empty());
        let parsed = Addr::parse(&flagged.serialize())?;
        assert_eq!(parsed, flagged);
        assert_eq!(parsed.callsign(), &call);
        assert_eq!(Addr::new("M0THC-0")?, Addr::new("M0THC")?);
        Ok(())
    }

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
                    callsign: Callsign::new("WIDE1-1")?,
                    flags: AddrFlags::empty(),
                },
                Addr {
                    callsign: Callsign::new("WIDE2-1")?,
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
        let a = Addr::new("M0THC")?.serialize_with_flags(AddrFlags::LAST);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 97]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC");

        let a = Addr::new("M0THC-0")?.serialize_with_flags(AddrFlags::LAST);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 97]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC");

        let a = Addr::new("M0THC-1")?.serialize_with_flags(AddrFlags::LAST);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 99]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC-1");

        let a = Addr::new("M0THC-2")?.serialize_with_flags(AddrFlags::HIGH);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 100 + 0x80]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC-2");

        let a = Addr::new("M0THC-3")?.serialize_with_flags(AddrFlags::EXTENDED);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 38]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC-3");

        let a = Addr::new("M0THC-4")?.serialize_with_flags(AddrFlags::DAMA);
        assert_eq!(a, vec![154, 96, 168, 144, 134, 64, 72]);
        assert_eq!(Addr::parse(&a)?.call(), "M0THC-4");
        Ok(())
    }

    #[test]
    fn addr_parse_rejects_callsign_low_bits() -> Result<()> {
        for call in ["M0THC", "ABCDEF"] {
            let valid = Addr::new(call)?.serialize_with_flags(AddrFlags::LAST);
            assert_eq!(Addr::parse(&valid)?.call(), call);
            for index in 0..6 {
                let mut invalid = valid.clone();
                invalid[index] |= 1;
                assert!(
                    matches!(
                        Addr::parse(&invalid),
                        Err(Error::InvalidSerializedCallsign(bytes)) if bytes == invalid
                    ),
                    "accepted low bit at callsign octet {index} in {call}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn addr_parse_rejects_invalid_lengths() {
        for length in (0..=10).filter(|&length| length != 7) {
            let invalid = vec![0x40; length];
            assert!(matches!(
                Addr::parse(&invalid),
                Err(Error::InvalidSerializedCallsign(bytes)) if bytes == invalid
            ));
        }
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
                assert_eq!(addr.serialize(), expected);
                let parsed = Addr::parse(&expected)?;
                assert_eq!(parsed, addr);
                assert_eq!(parsed.flags, flags);
                assert_eq!(parsed.serialize(), expected);
                // Explicit serialization flags override the stored flags.
                assert_eq!(
                    addr.serialize_with_flags(AddrFlags::empty())[6],
                    0x60 | (ssid << 1)
                );
                assert_eq!(addr.flags, flags);
                assert_eq!(addr.serialize(), expected);
            }
        }
        Ok(())
    }

    #[test]
    fn addr_flag_builders_preserve_other_flags() -> Result<()> {
        let reserved = AddrFlags::EXTENDED | AddrFlags::DAMA;
        let addr = Addr::new_bits("M0THC", reserved)?
            .with_highbit(true)
            .with_lowbit(true);
        assert_eq!(addr.flags, reserved | AddrFlags::HIGH | AddrFlags::LAST);
        assert_eq!(
            addr.clone().with_highbit(false).flags,
            reserved | AddrFlags::LAST
        );
        assert_eq!(
            addr.clone().with_lowbit(false).flags,
            reserved | AddrFlags::HIGH
        );
        assert_eq!(addr.with_highbit(false).with_lowbit(false).flags, reserved);
        Ok(())
    }

    #[test]
    fn packet_serialization_uses_stored_mode() -> Result<()> {
        for (extended, poll) in [
            (false, PollFinal::Clear),
            (false, PollFinal::Set),
            (true, PollFinal::Clear),
            (true, PollFinal::Set),
        ] {
            let (nr, ns) = if extended { (101, 109) } else { (5, 6) };
            let types = [
                PacketType::Iframe(Iframe {
                    nr,
                    ns,
                    poll,
                    pid: NO_L3,
                    payload: b"hello".to_vec(),
                }),
                PacketType::Rr(Rr { poll, nr }),
                PacketType::Rnr(Rnr { poll, nr }),
                PacketType::Rej(Rej { nr: 0, poll }),
                PacketType::Srej(Srej { nr: 0, poll }),
            ];
            for packet_type in types {
                let mut packet = Packet::ui(Callsign::new("LOCAL")?, Callsign::new("REMOTE")?, []);
                packet.packet_type = packet_type;
                packet = packet.with_extended(extended);
                let bytes = packet.serialize();
                assert_eq!(bytes[13] & 0x40 == 0, extended);
                let control_length = if extended { 2 } else { 1 };
                let payload_length = if matches!(packet.packet_type, PacketType::Iframe(_)) {
                    1 + b"hello".len()
                } else {
                    0
                };
                assert_eq!(bytes.len(), 14 + control_length + payload_length);
                let without_hint = packet.serialize_with_linux_extended_hint(false);
                let mut expected = bytes.clone();
                expected[13] |= 0x40;
                assert_eq!(without_hint, expected);
                assert_eq!(
                    Packet::parse(&without_hint, Some(extended))?.packet_type,
                    packet.packet_type
                );
                assert_eq!(Packet::parse(&bytes, None)?.packet_type, packet.packet_type);
                assert_eq!(
                    Packet::parse(&bytes, Some(extended))?.modulus,
                    packet.modulus
                );
                let mut conflicting_hint = bytes.clone();
                conflicting_hint[13] ^= 0x40;
                let parsed = Packet::parse(&conflicting_hint, Some(extended))?;
                assert_eq!(parsed.modulus, packet.modulus);
                assert_eq!(parsed.src.flags.contains(AddrFlags::EXTENDED), !extended);
                assert_eq!(parsed.serialize(), bytes);
                assert_eq!(
                    packet
                        .with_extended(!extended)
                        .with_extended(extended)
                        .serialize(),
                    bytes
                );
            }
        }
        Ok(())
    }

    #[test]
    fn packet_command_response_setter_preserves_other_flags() -> Result<()> {
        let flags = AddrFlags::LAST | AddrFlags::EXTENDED | AddrFlags::DAMA;
        let mut packet = Packet::ui(
            Addr::new_bits("M0AAA", flags)?,
            Addr::new_bits("M0BBB", flags)?,
            b"hello",
        );
        for command in [true, false, true] {
            packet.set_command_response(CommandResponse::from(command));
            assert_eq!(packet.command_response(), command);
            assert_eq!(packet.command_response_src(), !command);
            assert_eq!(packet.dst.flags, flags.with(AddrFlags::HIGH, command));
            assert_eq!(packet.src.flags, flags.with(AddrFlags::HIGH, !command));
            let bytes = packet.serialize();
            assert_eq!(bytes[6] & 0x80 != 0, command);
            assert_eq!(bytes[13] & 0x80 != 0, !command);
        }
        Ok(())
    }

    #[test]
    fn packet_command_response_bits_round_trip_independently() -> Result<()> {
        let packet = Packet::ui(Addr::new("M0AAA")?, Addr::new("M0BBB")?, b"hello");
        for destination_c in [false, true] {
            for source_c in [false, true] {
                let mut bytes = packet.serialize();
                bytes[6] = (bytes[6] & 0x7f) | (u8::from(destination_c) << 7);
                bytes[13] = (bytes[13] & 0x7f) | (u8::from(source_c) << 7);

                let parsed = Packet::parse(&bytes, None)?;
                assert_eq!(parsed.command_response(), destination_c);
                assert_eq!(parsed.command_response_src(), source_c);
                assert_eq!(parsed.serialize(), bytes);
            }
        }
        Ok(())
    }

    #[test]
    fn packet_destination_reserved_bit_uses_address_flags() -> Result<()> {
        let mut packet = Packet::ui(Addr::new("M0AAA")?, Addr::new("M0BBB")?, b"hello");
        for extended in [false, true, false] {
            packet.dst.flags = packet.dst.flags.with(AddrFlags::EXTENDED, extended);
            let bytes = packet.serialize();
            assert_eq!(bytes[6] & 0x40 == 0, extended);
            assert_eq!(packet.serialize_with_linux_extended_hint(false), bytes);

            let parsed = Packet::parse(&bytes, None)?;
            assert_eq!(parsed.dst.flags.contains(AddrFlags::EXTENDED), extended);
            assert_eq!(parsed.modulus, Modulus::Standard);
            assert_eq!(parsed.serialize(), bytes);
        }
        Ok(())
    }

    #[test]
    fn serialize_sabm() -> Result<()> {
        let src = Addr::new("M0THC-1")?;
        let dst = Addr::new("M0THC-2")?;
        assert_eq!(
            Packet {
                src: src.clone().with_highbit(false),
                dst: dst.clone().with_highbit(true),
                modulus: Modulus::Standard,
                digipeater: vec![],
                packet_type: PacketType::Sabm(Sabm {
                    poll: PollFinal::Set
                })
            }
            .serialize(),
            vec![
                154, 96, 168, 144, 134, 64, 228, // dst
                154, 96, 168, 144, 134, 64, 99, // src
                63
            ], //, 111, 212]
        );
        assert_eq!(
            Packet {
                digipeater: vec![],
                modulus: Modulus::Standard,
                src: src.with_highbit(false),
                dst: dst.with_highbit(true),
                packet_type: PacketType::Sabm(Sabm {
                    poll: PollFinal::Clear
                })
            }
            .serialize(),
            vec![
                154, 96, 168, 144, 134, 64, 228, 154, 96, 168, 144, 134, 64, 99, 47
            ], // , 238, 196]
        );
        Ok(())
    }

    #[test]
    fn serialize_ui_repeat() -> Result<()> {
        let src = Addr::new("M0THC-1")?;
        let dst = Addr::new("M0THC-2")?.with_highbit(true);
        let packet = Packet {
            src: src.clone().with_highbit(false),
            dst: dst.clone().with_highbit(true),
            modulus: Modulus::Standard,
            digipeater: vec![
                Addr::new("WIDE1-1")?.with_highbit(true),
                Addr::new("WIDE2-2")?.with_lowbit(true),
            ],
            packet_type: PacketType::Ui(Ui {
                pid: 0xF0,
                push: PollFinal::Clear,
                payload: "yo".into(),
            }),
        };
        let got = packet.serialize();
        assert_eq!(
            got,
            vec![
                154, 96, 168, 144, 134, 64, 228, // dst
                154, 96, 168, 144, 134, 64, 98, // src
                174, 146, 136, 138, 98, 64, 226, // rpt1, already repeated
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
