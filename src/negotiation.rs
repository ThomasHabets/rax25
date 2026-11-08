//! Opt-in AX.25 XID policy and the resulting directional link limits.
use std::time::Duration;

use crate::xid::XidParameters;
use crate::{Error, Result};

pub(crate) const REJ: u32 = 0x0000_0002;
pub(crate) const SREJ: u32 = 0x0000_0004;
pub(crate) const MULTI_SREJ: u32 = 0x0020_0000;
pub(crate) const MOD8: u32 = 0x0000_0400;
pub(crate) const MOD128: u32 = 0x0000_0800;
const REQUIRED: u32 = 0x0002_a080;

/// Local receive capabilities and management retry policy.
/// SREJ is permitted by default, but requires a successful XID exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XidConfig {
    /// Allow single- and multi-frame selective reject on this connection.
    pub srej: bool,
    pub receive_length: usize,
    pub receive_window: u8,
    pub receive_window_extended: u8,
    pub acknowledgement_timer: Duration,
    pub retries: u8,
    pub management_timeout: Duration,
    /// Retransmissions after the initial XID command.
    pub management_retries: u8,
}

impl Default for XidConfig {
    fn default() -> Self {
        Self {
            srej: true,
            receive_length: 256,
            receive_window: 4,
            receive_window_extended: 32,
            acknowledgement_timer: Duration::from_secs(3),
            retries: 10,
            management_timeout: Duration::from_secs(3),
            management_retries: 3,
        }
    }
}

impl XidConfig {
    /// Reject invalid policy before opening a connection or emitting frames.
    ///
    /// # Errors
    ///
    /// There are many ways XID could be invalid, and they should all be encoded
    /// into [`Error::InvalidXidConfig`].
    pub fn validate(&self) -> Result<()> {
        if !(1..=(u32::MAX / 8) as usize).contains(&self.receive_length) {
            return Err(Error::InvalidXidConfig("invalid XID receive length"));
        }
        if !(1..=7).contains(&self.receive_window) {
            return Err(Error::InvalidXidConfig("invalid modulo-8 window"));
        }
        if !(1..=127).contains(&self.receive_window_extended) {
            return Err(Error::InvalidXidConfig("invalid modulo-128 window"));
        }
        for duration in [self.acknowledgement_timer, self.management_timeout] {
            if duration < Duration::from_millis(1) || duration.as_millis() > u128::from(u32::MAX) {
                return Err(Error::InvalidXidConfig("invalid XID timer"));
            }
        }
        if self.retries == 0 {
            return Err(Error::InvalidXidConfig("invalid XID retry count"));
        }
        Ok(())
    }

    pub(crate) fn offer(&self, extended: bool) -> XidParameters {
        XidParameters {
            classes: Some(0x0021),
            optional_functions: Some(
                REQUIRED
                    | REJ
                    | if self.srej { SREJ | MULTI_SREJ } else { 0 }
                    | if extended { MOD128 } else { MOD8 },
            ),
            receive_length_bits: Some(
                u32::try_from(self.receive_length * 8).expect("validated receive length"),
            ),
            receive_window: Some(self.window(extended, self.srej)),
            acknowledgement_timer_ms: Some(
                u32::try_from(self.acknowledgement_timer.as_millis()).expect("validated timer"),
            ),
            retries: Some(self.retries),
        }
    }

    pub(crate) fn negotiate(
        &self,
        peer: &XidParameters,
        extended: bool,
        mtu: usize,
    ) -> Option<NegotiatedParameters> {
        // 2017 section 6.3.2: omitted functions default to SREJ/modulo-128.
        let functions = peer.optional_functions.unwrap_or(REQUIRED | SREJ | MOD128);
        let classes = peer.classes.unwrap_or(0x21);
        // Interoperability: Dire Wolf selects multi-SREJ with bit 21 alone,
        // clearing both REJ and single-SREJ despite 2017's PI=3 prose requiring
        // one of those two. Treat the explicit multi-SREJ bit as a valid choice.
        let reject_mode = if self.srej && functions & MULTI_SREJ != 0 {
            RejectMode::MultiSrej
        } else if self.srej && functions & SREJ != 0 {
            RejectMode::Srej
        } else if functions & REJ != 0 {
            RejectMode::Rej
        } else {
            return None;
        };
        if classes & 1 == 0 || !matches!(classes & 0x60, 0x20 | 0x40) {
            return None;
        }
        let extended = extended && functions & MOD128 != 0;
        if !extended && functions & MOD8 == 0 {
            return None;
        }
        let receive_length = peer.receive_length_bits.unwrap_or(2048);
        let window = peer.receive_window.unwrap_or(if extended { 32 } else { 4 });
        let timer = peer.acknowledgement_timer_ms.unwrap_or(3000);
        let retries = peer.retries.unwrap_or(10);
        if receive_length < 8 || window == 0 || window > 127 || timer == 0 || retries == 0 {
            return None;
        }
        Some(NegotiatedParameters {
            extended,
            reject_mode,
            receive_length: self.receive_length,
            transmit_length: mtu.min((receive_length / 8) as usize).max(1),
            receive_window: self.window(extended, reject_mode != RejectMode::Rej),
            transmit_window: window.min(self.window(extended, reject_mode != RejectMode::Rej)),
            acknowledgement_timer: self
                .acknowledgement_timer
                .max(Duration::from_millis(u64::from(timer))),
            retries: self.retries.max(retries),
        })
    }

    fn window(&self, extended: bool, selective: bool) -> u8 {
        let (window, modulus) = if extended {
            (self.receive_window_extended, 128)
        } else {
            (self.receive_window, 8)
        };
        // Selective repeat must distinguish old duplicates from future frames.
        window.min(if selective { modulus / 2 } else { modulus - 1 })
    }
}

/// Recovery method selected by XID. Unnegotiated links use REJ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectMode {
    Rej,
    Srej,
    MultiSrej,
}

impl RejectMode {
    pub(crate) fn bit(self) -> u32 {
        match self {
            Self::Rej => REJ,
            Self::Srej => SREJ,
            Self::MultiSrej => MULTI_SREJ,
        }
    }
}

/// Negotiated local receive limits and peer-imposed transmit limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedParameters {
    pub extended: bool,
    pub reject_mode: RejectMode,
    pub receive_length: usize,
    pub transmit_length: usize,
    pub receive_window: u8,
    pub transmit_window: u8,
    pub acknowledgement_timer: Duration,
    pub retries: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directional_limits_and_negotiated_maxima() {
        let local = XidConfig::default();
        let peer = XidConfig {
            receive_length: 64,
            receive_window_extended: 12,
            acknowledgement_timer: Duration::from_secs(5),
            retries: 15,
            ..XidConfig::default()
        };
        let result = local.negotiate(&peer.offer(true), true, 128).unwrap();
        assert_eq!(result.receive_length, 256);
        assert_eq!(result.transmit_length, 64);
        assert_eq!(result.receive_window, 32);
        assert_eq!(result.transmit_window, 12);
        assert_eq!(result.acknowledgement_timer, Duration::from_secs(5));
        assert_eq!(result.retries, 15);
        assert!(result.extended);
    }

    #[test]
    fn unsupported_and_invalid_offers_are_not_accepted() {
        let local = XidConfig::default();
        let mut peer = local.offer(true);
        peer.optional_functions = Some(MOD128);
        assert!(local.negotiate(&peer, true, 256).is_none());
        peer = local.offer(true);
        peer.classes = Some(0x61);
        assert!(local.negotiate(&peer, true, 256).is_none());
        peer = local.offer(true);
        peer.receive_length_bits = Some(7);
        assert!(local.negotiate(&peer, true, 256).is_none());
        peer = local.offer(true);
        peer.receive_window = Some(0);
        assert!(local.negotiate(&peer, true, 256).is_none());
        assert_eq!(
            local
                .negotiate(&XidParameters::default(), true, 256)
                .unwrap()
                .reject_mode,
            RejectMode::Srej
        );
    }

    #[test]
    fn standard_mode_and_local_transmit_caps_are_preserved() {
        let config = XidConfig::default();
        let result = config.negotiate(&config.offer(false), true, 32).unwrap();
        assert!(!result.extended);
        assert_eq!(result.transmit_length, 32);
        assert_eq!(result.transmit_window, 4);
    }

    #[test]
    fn invalid_config_returns_typed_errors() {
        for (config, reason) in [
            (
                XidConfig {
                    receive_length: 0,
                    ..XidConfig::default()
                },
                "invalid XID receive length",
            ),
            (
                XidConfig {
                    receive_window: 8,
                    ..XidConfig::default()
                },
                "invalid modulo-8 window",
            ),
            (
                XidConfig {
                    receive_window_extended: 128,
                    ..XidConfig::default()
                },
                "invalid modulo-128 window",
            ),
            (
                XidConfig {
                    acknowledgement_timer: Duration::ZERO,
                    ..XidConfig::default()
                },
                "invalid XID timer",
            ),
            (
                XidConfig {
                    management_timeout: Duration::ZERO,
                    ..XidConfig::default()
                },
                "invalid XID timer",
            ),
            (
                XidConfig {
                    retries: 0,
                    ..XidConfig::default()
                },
                "invalid XID retry count",
            ),
        ] {
            assert!(
                matches!(config.validate(), Err(Error::InvalidXidConfig(actual)) if actual == reason)
            );
        }
        assert!(XidConfig::default().validate().is_ok());
    }

    #[test]
    fn invalid_config_is_rejected() {
        assert!(
            XidConfig {
                receive_length: 0,
                ..XidConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            XidConfig {
                receive_window: 8,
                ..XidConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            XidConfig {
                management_timeout: Duration::ZERO,
                ..XidConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            XidConfig {
                retries: 0,
                ..XidConfig::default()
            }
            .validate()
            .is_err()
        );
    }
}
