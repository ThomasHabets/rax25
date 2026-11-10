//! AX.25 XID parameter information fields (section 4.3.3.7).
//!
//! Capability bitfields use little-endian octet order; numeric parameters and
//! group lengths are big-endian. Figure 4.5 numbers capability bits from 1 in
//! 1998 (pages 25-26), but from 0 in 2017 (pages 32-33). This renumbering does
//! not change their wire positions or masks. For example, ABM is bit 1/0 with
//! mask 0x0001, half duplex is bit 6/5 with mask 0x0020, and modulo-128 is bit
//! 12/11 with mask 0x000800 (1998/2017 numbering respectively).
//!
//! 1998 Spec bug: The 1998 optional-functions prose incorrectly calls REJ/SREJ
//! bits 1 and 2; its table assigns bits 2 and 3.
//!
//! The 2017 table enables multiframe SREJ and adds a segmentation capability;
//! see the corresponding flags below.
//!
//! 2017 Spec bug: Retries parameter (PI=10) from Figure 4.5, although its
//! prose and example still use it.

use crate::{Error, Result};

macro_rules! capability_flags {
    ($(#[$doc:meta])* $name:ident, $integer:ty, {$($(#[$flag_doc:meta])* $flag:ident = $value:expr;)*}) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct $name($integer);

        impl $name {
            $($(#[$flag_doc])* pub const $flag: Self = Self($value);)*

            /// Construct flags without discarding unknown or reserved bits.
            #[must_use]
            pub const fn from_bits_retain(bits: $integer) -> Self { Self(bits) }

            /// Return the table-numbered bit mask.
            #[must_use]
            pub const fn bits(self) -> $integer { self.0 }

            /// Whether every flag in `other` is set.
            #[must_use]
            pub const fn contains(self, other: Self) -> bool {
                self.0 & other.0 == other.0
            }
        }

        impl std::ops::BitOr for $name {
            type Output = Self;
            fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
        }

        impl std::ops::BitAnd for $name {
            type Output = Self;
            fn bitand(self, rhs: Self) -> Self { Self(self.0 & rhs.0) }
        }
    };
}

capability_flags! {
    /// Classes-of-procedures bits from Figure 4.5 (PI=2).
    ClassesOfProcedures, u16, {
        /// Asynchronous balanced mode.
        ABM = 0x0001;
        /// Half-duplex operation.
        HALF_DUPLEX = 0x0020;
        /// Full-duplex operation.
        FULL_DUPLEX = 0x0040;
    }
}

capability_flags! {
    /// HDLC optional-functions bits from Figure 4.5 (PI=3).
    OptionalFunctions, u32, {
        /// Implicit reject.
        REJ = 0x0000_0002;
        /// Selective reject.
        SREJ = 0x0000_0004;
        /// Extended addressing.
        EXTENDED_ADDRESS = 0x0000_0080;
        /// Modulo-8 sequence numbers.
        MODULO_8 = 0x0000_0400;
        /// Modulo-128 sequence numbers.
        MODULO_128 = 0x0000_0800;
        /// TEST commands and responses.
        TEST = 0x0000_2000;
        /// 16-bit frame check sequence.
        FCS_16 = 0x0000_8000;
        /// Synchronous transmission.
        SYNCHRONOUS_TRANSMIT = 0x0002_0000;
        /// Multi-frame selective reject: bit 22 in 1998, bit 21 in 2017.
        /// The 1998 table requires zero; the 2017 table permits either value.
        MULTI_SREJ = 0x0020_0000;
        /// Segmenter/reassembler: bit 22 in 2017, formerly reserved in 1998.
        /// The 2017 table permits either value, but its following prose still
        /// says this bit must be zero. Exposing the flag does not enable the
        /// unimplemented segmentation service.
        SEGMENTER = 0x0040_0000;
    }
}

/// Parameters present in an XID parameter-negotiation group.
///
/// `None` means omitted (retain the current setting), not a zero value. Parsing
/// a zero-length parameter resolves it to its AX.25 default. This codec does not
/// validate capabilities or apply negotiated values to a connection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XidParameters {
    /// Table-numbered bits; see [`ClassesOfProcedures`].
    pub classes: Option<u16>,
    /// Table-numbered bits; see [`OptionalFunctions`]. Must fit in 24 bits.
    pub optional_functions: Option<u32>,
    pub receive_length_bits: Option<u32>,
    pub receive_window: Option<u8>,
    pub acknowledgement_timer_ms: Option<u32>,
    pub retries: Option<u8>,
}

impl XidParameters {
    /// AX.25 defaults for an empty group or zero-length parameters.
    ///
    /// These are the 1998 defaults: combined SREJ/REJ and modulo-8. The 2017
    /// prose instead specifies selective reject and modulo-128, and drops the
    /// explicit combined-mode selection rule. No revision identifier in this
    /// information field distinguishes the two interpretations; this codec
    /// retains the 1998 baseline. Connection policy must still check whether
    /// the resolved capabilities are actually supported.
    ///
    /// The default receive window is modulo-8's 4. A zero-length window field
    /// in a group explicitly selecting modulo-128 instead resolves to 32.
    #[must_use]
    pub fn protocol_defaults() -> Self {
        Self {
            classes: Some((ClassesOfProcedures::ABM | ClassesOfProcedures::HALF_DUPLEX).bits()),
            optional_functions: Some(
                (OptionalFunctions::REJ
                    | OptionalFunctions::SREJ
                    | OptionalFunctions::EXTENDED_ADDRESS
                    | OptionalFunctions::MODULO_8
                    | OptionalFunctions::TEST
                    | OptionalFunctions::FCS_16
                    | OptionalFunctions::SYNCHRONOUS_TRANSMIT)
                    .bits(),
            ),
            receive_length_bits: Some(2048),
            receive_window: Some(4),
            acknowledgement_timer_ms: Some(3000),
            retries: Some(10),
        }
    }

    /// Parse a complete information field, ignoring unknown groups and PIs.
    ///
    /// Truncated groups/TLVs, unsupported format identifiers, duplicate known
    /// groups/parameters, and oversized known parameter values are errors.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 || bytes.first() != Some(&0x82) {
            return Err(Error::InvalidXid("invalid XID format identifier"));
        }
        let mut bytes = &bytes[1..];
        let mut result = Self::default();
        let mut found = false;
        while !bytes.is_empty() {
            let header = take(&mut bytes, 3)?;
            let length = usize::from(u16::from_be_bytes([header[1], header[2]]));
            let group = take(&mut bytes, length)?;
            if header[0] != 0x80 {
                continue;
            }
            if found {
                return Err(Error::InvalidXid(
                    "duplicate XID parameter-negotiation group",
                ));
            }
            found = true;
            result = Self::parse_group(group)?;
        }
        Ok(result)
    }

    fn parse_group(mut bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Ok(Self::protocol_defaults());
        }
        let defaults = Self::protocol_defaults();
        let mut result = Self::default();
        let mut seen = [false; 11];
        let mut default_window = false;
        while !bytes.is_empty() {
            let header = take(&mut bytes, 2)?;
            let id = header[0];
            let value = take(&mut bytes, usize::from(header[1]))?;
            if !matches!(id, 2 | 3 | 6 | 8 | 9 | 10) {
                continue;
            }
            if std::mem::replace(&mut seen[usize::from(id)], true) {
                return Err(Error::DuplicateXidParameter(id));
            }
            match id {
                2 => {
                    result.classes = Some(if value.is_empty() {
                        defaults.classes.unwrap()
                    } else {
                        let value: [u8; 2] = value.try_into().map_err(|_| {
                            Error::InvalidXid("invalid XID classes-of-procedures length")
                        })?;
                        u16::from_le_bytes(value)
                    });
                }
                3 => {
                    result.optional_functions = Some(if value.is_empty() {
                        defaults.optional_functions.unwrap()
                    } else {
                        if value.len() != 3 {
                            return Err(Error::InvalidXid("invalid XID optional-functions length"));
                        }
                        let mut octets = [0; 4];
                        octets[..value.len()].copy_from_slice(value);
                        u32::from_le_bytes(octets)
                    });
                }
                6 => {
                    result.receive_length_bits = Some(number(value, 4, 2048)?);
                }
                8 => {
                    default_window = value.is_empty();
                    result.receive_window = Some(u8::try_from(number(value, 1, 4)?)?);
                }
                9 => {
                    result.acknowledgement_timer_ms = Some(number(value, 4, 3000)?);
                }
                10 => result.retries = Some(u8::try_from(number(value, 4, 10)?)?),
                _ => unreachable!(),
            }
        }
        if default_window
            && result.optional_functions.is_some_and(|v| {
                let flags = OptionalFunctions::from_bits_retain(v);
                flags.contains(OptionalFunctions::MODULO_128)
                    && !flags.contains(OptionalFunctions::MODULO_8)
            })
        {
            result.receive_window = Some(32);
        }
        Ok(result)
    }

    /// Serialize known parameters in ascending PI order.
    ///
    /// Unknown groups and parameters are not retained. An all-`None` value is
    /// encoded as an empty group, which reparses as explicit protocol defaults.
    ///
    /// # Panics
    /// Panics if `optional_functions` contains bits outside its 24-bit field.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut group = Vec::new();
        if let Some(value) = self.classes {
            parameter(&mut group, 2, &value.to_le_bytes());
        }
        if let Some(value) = self.optional_functions {
            assert_eq!(
                value & 0xff00_0000,
                0,
                "XID optional functions exceed 24 bits"
            );
            let bytes = value.to_le_bytes();
            parameter(&mut group, 3, &bytes[..3]);
        }
        if let Some(value) = self.receive_length_bits {
            numeric_parameter(&mut group, 6, value);
        }
        if let Some(value) = self.receive_window {
            parameter(&mut group, 8, &[value]);
        }
        if let Some(value) = self.acknowledgement_timer_ms {
            numeric_parameter(&mut group, 9, value);
        }
        if let Some(value) = self.retries {
            parameter(&mut group, 10, &[value]);
        }
        let length = u16::try_from(group.len()).expect("XID parameters have bounded length");
        let mut bytes = vec![0x82, 0x80];
        bytes.extend(length.to_be_bytes());
        bytes.extend(group);
        bytes
    }
}

fn take<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8]> {
    let Some((value, rest)) = bytes.split_at_checked(length) else {
        return Err(Error::InvalidXid("truncated XID group or parameter"));
    };
    *bytes = rest;
    Ok(value)
}

fn number(bytes: &[u8], maximum_length: usize, default: u32) -> Result<u32> {
    if bytes.is_empty() {
        return Ok(default);
    }
    if bytes.len() > maximum_length {
        return Err(Error::InvalidXid("oversized XID numeric parameter"));
    }
    Ok(bytes
        .iter()
        .fold(0, |value, byte| (value << 8) | u32::from(*byte)))
}

fn parameter(bytes: &mut Vec<u8>, id: u8, value: &[u8]) {
    bytes.push(id);
    bytes.push(u8::try_from(value.len()).expect("XID parameter has bounded length"));
    bytes.extend(value);
}

fn numeric_parameter(bytes: &mut Vec<u8>, id: u8, value: u32) {
    let bytes_be = value.to_be_bytes();
    let start = bytes_be.iter().position(|byte| *byte != 0).unwrap_or(3);
    parameter(bytes, id, &bytes_be[start..]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Addr, CommandResponse, Packet, PacketType, PollFinal};

    // Independently derived from Fig. 4.5's bit numbers and verified against
    // Dire Wolf masks (which represent bitfields as BE integers):
    // https://github.com/wb2osz/direwolf/blob/master/src/xid.c
    // Not the inconsistent Fig. 4.6 samples: 1998 has 00 20 / 86 a8 02;
    // 2017 has 22 00 / 82 a8 22. ABM+half-duplex is 21 00 by the bit table.
    const FIXTURE: &[u8] = &[
        0x82, 0x80, 0, 23, 2, 2, 0x21, 0, 3, 3, 0x82, 0xa8, 2, 6, 2, 4, 0, 8, 1, 2, 9, 2, 0x10, 0,
        10, 1, 3,
    ];

    fn fixture_parameters() -> XidParameters {
        XidParameters {
            classes: Some(0x0021),
            optional_functions: Some(0x02_a882),
            receive_length_bits: Some(1024),
            receive_window: Some(2),
            acknowledgement_timer_ms: Some(4096),
            retries: Some(3),
        }
    }

    #[test]
    fn independent_wire_fixture() {
        assert_eq!(XidParameters::parse(FIXTURE).unwrap(), fixture_parameters());
        assert_eq!(fixture_parameters().serialize(), FIXTURE);
        let classes = ClassesOfProcedures::ABM | ClassesOfProcedures::HALF_DUPLEX;
        assert_eq!(classes.bits(), 0x0021);
        assert!(classes.contains(ClassesOfProcedures::ABM));
        assert!(!classes.contains(ClassesOfProcedures::FULL_DUPLEX));
        let functions = OptionalFunctions::REJ
            | OptionalFunctions::EXTENDED_ADDRESS
            | OptionalFunctions::MODULO_128
            | OptionalFunctions::TEST
            | OptionalFunctions::FCS_16
            | OptionalFunctions::SYNCHRONOUS_TRANSMIT;
        assert_eq!(
            functions.bits(),
            fixture_parameters().optional_functions.unwrap()
        );
    }

    #[test]
    fn packet_round_trips() {
        for parameters in [None, Some(fixture_parameters())] {
            for command in [CommandResponse::Response, CommandResponse::Command] {
                for poll in [PollFinal::Clear, PollFinal::Set] {
                    let packet = Packet::xid(
                        Addr::new("N0CALL").unwrap(),
                        Addr::new("N1CALL").unwrap(),
                        command,
                        poll,
                        parameters.clone(),
                    );
                    for ext in [false, true] {
                        let bytes = packet.clone().with_extended(ext).serialize();
                        assert_eq!(bytes[13] & 0x40 == 0, ext);
                        assert_eq!(bytes[14], if poll.is_set() { 0xbf } else { 0xaf });
                        assert_eq!(bytes[6] & 0x80 != 0, command.is_command());
                        assert_eq!(bytes[13] & 0x80 != 0, command.is_response());
                        assert_eq!(
                            Packet::parse(&bytes, Some(ext)).unwrap().packet_type(),
                            &PacketType::Xid(crate::Xid {
                                poll,
                                parameters: parameters.clone()
                            })
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn defaults_and_omission() {
        assert_eq!(
            XidParameters::parse(&[0x82, 0x80, 0, 0]).unwrap(),
            XidParameters::protocol_defaults()
        );
        let empty = XidParameters::default();
        assert_eq!(empty.serialize(), [0x82, 0x80, 0, 0]);
        assert_eq!(
            XidParameters::parse(&empty.serialize()).unwrap(),
            XidParameters::protocol_defaults()
        );
        let defaults = [0x82, 0x80, 0, 12, 2, 0, 3, 0, 6, 0, 8, 0, 9, 0, 10, 0];
        assert_eq!(
            XidParameters::parse(&defaults).unwrap(),
            XidParameters::protocol_defaults()
        );
        let extended = [0x82, 0x80, 0, 7, 8, 0, 3, 3, 0x82, 0xa8, 2];
        assert_eq!(
            XidParameters::parse(&extended).unwrap().receive_window,
            Some(32)
        );
    }

    #[test]
    fn unknown_groups_and_parameters() {
        let mut bytes = vec![0x82, 0x42, 0, 3, 0xff, 0xff, 0xff];
        bytes.extend(&FIXTURE[1..]);
        bytes.extend([0x43, 0, 0]);
        assert_eq!(XidParameters::parse(&bytes).unwrap(), fixture_parameters());
        assert_eq!(
            XidParameters::parse(&[0x82, 0x80, 0, 5, 0xff, 3, 1, 2, 3]).unwrap(),
            XidParameters::default()
        );
    }

    #[test]
    fn malformed_fields_return_typed_errors() {
        assert!(matches!(
            XidParameters::parse(&[]),
            Err(Error::InvalidXid("invalid XID format identifier"))
        ));
        assert!(matches!(
            XidParameters::parse(&[0x82, 0x80, 0, 3, 2, 1, 0]),
            Err(Error::InvalidXid(
                "invalid XID classes-of-procedures length"
            ))
        ));
        assert!(matches!(
            XidParameters::parse(&[0x82, 0x80, 0, 4, 2, 0, 2, 0]),
            Err(Error::DuplicateXidParameter(2))
        ));
        assert!(matches!(
            XidParameters::parse(&[0x82, 0x80, 0, 0, 0x80, 0, 0]),
            Err(Error::InvalidXid(
                "duplicate XID parameter-negotiation group"
            ))
        ));
        assert!(matches!(
            XidParameters::parse(&[0x82, 0x80, 0, 4, 10, 2, 1, 0]),
            Err(Error::IntegerConversion(_))
        ));
    }

    #[test]
    fn malformed_fields() {
        for bytes in [
            &[][..],
            &[0],
            &[0x82, 0x80],
            &[0x82, 0x80, 0],
            &[0x82, 0x80, 0, 1],
            &[0x82, 0x80, 0, 1, 2],
            &[0x82, 0x80, 0, 3, 2, 2, 0],
            &[0x82, 0x80, 0, 3, 2, 1, 0],
            &[0x82, 0x80, 0, 4, 3, 2, 0, 0],
            &[0x82, 0x80, 0, 6, 3, 4, 0, 0, 0, 0],
            &[0x82, 0x80, 0, 4, 8, 2, 0, 1],
            &[0x82, 0x80, 0, 4, 10, 2, 1, 0],
            &[0x82, 0x80, 0, 7, 6, 5, 0, 0, 0, 0, 1],
            &[0x82, 0x80, 0, 7, 9, 5, 0, 0, 0, 0, 1],
            &[0x82, 0x80, 0, 7, 10, 5, 0, 0, 0, 0, 1],
            &[0x82, 0x42, 0xff, 0xff],
            &[0x82, 0x80, 0, 4, 2, 0, 2, 0],
            &[0x82, 0x80, 0, 0, 0x80, 0, 0],
        ] {
            assert!(
                XidParameters::parse(bytes).is_err(),
                "accepted {bytes:02x?}"
            );
        }
        // Every proper nonempty prefix of a group containing TLVs is invalid.
        for length in 1..FIXTURE.len() {
            assert!(XidParameters::parse(&FIXTURE[..length]).is_err());
        }
    }

    #[test]
    fn numeric_limits_and_reserved_bits_round_trip() {
        let retries = [0x82, 0x80, 0, 6, 10, 4, 0, 0, 0, 255];
        assert_eq!(XidParameters::parse(&retries).unwrap().retries, Some(255));
        for value in [0, 1, 255, 256, 65535, 65536, u32::MAX] {
            let parameters = XidParameters {
                classes: Some(u16::MAX),
                optional_functions: Some(value & 0x00ff_ffff),
                receive_length_bits: Some(value),
                receive_window: Some(u8::MAX),
                acknowledgement_timer_ms: Some(value),
                retries: Some(u8::MAX),
            };
            assert_eq!(
                XidParameters::parse(&parameters.serialize()).unwrap(),
                parameters
            );
        }
    }

    #[test]
    fn packet_rejects_truncated_information() {
        let packet = Packet::xid(
            Addr::new("N0CALL").unwrap(),
            Addr::new("N1CALL").unwrap(),
            CommandResponse::Command,
            PollFinal::Set,
            Some(fixture_parameters()),
        );
        let bytes = packet.serialize();
        for length in 16..bytes.len() {
            assert!(Packet::parse(&bytes[..length], Some(false)).is_err());
        }
    }

    #[test]
    #[should_panic(expected = "XID optional functions exceed 24 bits")]
    fn optional_functions_must_fit_wire_field() {
        let _ = XidParameters {
            optional_functions: Some(0x0100_0000),
            ..XidParameters::default()
        }
        .serialize();
    }
}
