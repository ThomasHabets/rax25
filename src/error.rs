//! Typed errors returned by the library.

use std::io;

#[cfg(feature = "serial")]
use serialport::Error as SerialError;
#[cfg(all(feature = "async", not(feature = "serial")))]
use tokio_serial::Error as SerialError;

/// Result returned by library operations, with an optional custom error type.
///
/// ```
/// use rax25::{Addr, Error, Result};
///
/// fn address(value: &str) -> Result<Addr> {
///     Addr::new(value)
/// }
/// assert!(matches!(address("!"), Err(Error::InvalidCallsign(_))));
/// ```
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors from AX.25 parsing, connection management, and transport operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid callsign: {0}")]
    InvalidCallsign(String),
    #[error("invalid serialized callsign: {0:?}")]
    InvalidSerializedCallsign(Vec<u8>),
    #[error("packet too short: {length} bytes")]
    PacketTooShort { length: usize },
    #[error("AX.25 in ext mode, but S/U frame is too short")]
    ExtendedControlTooShort,
    #[error("connection timeout")]
    ConnectionTimeout,
    #[error("failed to broadcast")]
    BroadcastFailed,
    #[error("queue full")]
    QueueFull,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[cfg(any(feature = "serial", feature = "async"))]
    #[error("serial port error: {0}")]
    Serial(#[from] SerialError),
    #[cfg(any(feature = "serial", feature = "async"))]
    #[error("serial endpoint {endpoint}: {source}")]
    SerialEndpoint {
        endpoint: String,
        #[source]
        source: SerialError,
    },
    #[error("invalid integer: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
    #[error("integer conversion failed: {0}")]
    IntegerConversion(#[from] std::num::TryFromIntError),
    #[error("system time error: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error("receive failed: {0}")]
    Receive(#[from] std::sync::mpsc::RecvTimeoutError),
    #[cfg(feature = "async")]
    #[error("operation timed out: {0}")]
    Elapsed(#[from] tokio::time::error::Elapsed),
    #[error("endpoint {endpoint}: {source}")]
    Endpoint {
        endpoint: String,
        #[source]
        source: io::Error,
    },
    #[error("invalid endpoint {endpoint}: {reason}")]
    InvalidEndpoint {
        endpoint: String,
        reason: &'static str,
    },
    #[error("invalid XID: {0}")]
    InvalidXid(&'static str),
    #[error("duplicate XID parameter: {0:#04x}")]
    DuplicateXidParameter(u8),
    #[error("invalid XID configuration: {0}")]
    InvalidXidConfig(&'static str),
    #[error("impossible state encountered: {0}")]
    Impossible(String),
    #[error("KISS error: {0}")]
    Kiss(String),
    #[error("internal mutex was poisoned")]
    MutexPoisoned,
    #[error("unsupported AX.25 control field: {0:#04x}")]
    UnsupportedControl(u8),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn typed_parse_errors() {
        assert!(matches!(
            crate::Addr::new("!"),
            Err(Error::InvalidCallsign(call)) if call == "!"
        ));
        assert!(matches!(
            crate::Addr::parse(&[1, 2]),
            Err(Error::InvalidSerializedCallsign(bytes)) if bytes == [1, 2]
        ));
        assert!(matches!(
            crate::Packet::parse(&[0; 14], Some(false)),
            Err(Error::PacketTooShort { length: 14 })
        ));
        let mut frame = crate::Addr::new("M0AAA").unwrap().serialize();
        frame.extend(
            crate::Addr::new("M0BBB")
                .unwrap()
                .serialize_with_flags(crate::AddrFlags::LAST),
        );
        frame.push(0);
        assert!(matches!(
            crate::Packet::parse(&frame, Some(true)),
            Err(Error::ExtendedControlTooShort)
        ));
        assert!(matches!(
            crate::parse_duration("invalid"),
            Err(Error::ParseInt(_))
        ));
    }

    #[test]
    fn converted_errors_preserve_sources() {
        let error = Error::from(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
        assert!(matches!(&error, Error::Io(source) if source.kind() == io::ErrorKind::BrokenPipe));
        assert_eq!(error.source().unwrap().to_string(), "closed");

        let error = Error::from("invalid".parse::<u64>().unwrap_err());
        assert!(error.source().unwrap().is::<std::num::ParseIntError>());
        let error = Error::from(u8::try_from(256_u16).unwrap_err());
        assert!(error.source().unwrap().is::<std::num::TryFromIntError>());
        let error = Error::from(
            std::time::UNIX_EPOCH
                .duration_since(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1))
                .unwrap_err(),
        );
        assert!(error.source().unwrap().is::<std::time::SystemTimeError>());
        let error = Error::from(std::sync::mpsc::RecvTimeoutError::Disconnected);
        assert!(
            error
                .source()
                .unwrap()
                .is::<std::sync::mpsc::RecvTimeoutError>()
        );
    }

    #[test]
    fn endpoint_preserves_context_and_source() {
        let error = Error::Endpoint {
            endpoint: "tcp://localhost:8001".into(),
            source: io::Error::new(io::ErrorKind::ConnectionRefused, "refused"),
        };
        assert_eq!(error.to_string(), "endpoint tcp://localhost:8001: refused");
        assert_eq!(
            error
                .source()
                .unwrap()
                .downcast_ref::<io::Error>()
                .unwrap()
                .kind(),
            io::ErrorKind::ConnectionRefused
        );
    }

    #[cfg(any(feature = "serial", feature = "async"))]
    #[test]
    fn serial_conversion_preserves_source() {
        let serial = SerialError::from(io::Error::new(io::ErrorKind::NotFound, "missing port"));
        let error = Error::from(serial);
        assert!(matches!(&error, Error::Serial(_)));
        assert!(error.source().unwrap().is::<SerialError>());
        assert!(error.to_string().contains("missing port"));

        let error = Error::SerialEndpoint {
            endpoint: "serial:///missing".into(),
            source: SerialError::from(io::Error::new(io::ErrorKind::NotFound, "missing port")),
        };
        assert!(
            matches!(&error, Error::SerialEndpoint { endpoint, .. } if endpoint == "serial:///missing")
        );
        assert!(error.source().unwrap().is::<SerialError>());
        assert!(error.to_string().contains("serial:///missing"));
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn elapsed_conversion_preserves_source() {
        let elapsed = tokio::time::timeout(std::time::Duration::ZERO, std::future::pending::<()>())
            .await
            .unwrap_err();
        let error = Error::from(elapsed);
        assert!(matches!(&error, Error::Elapsed(_)));
        assert!(error.source().unwrap().is::<tokio::time::error::Elapsed>());
    }

    #[test]
    fn result_supports_custom_error_type() {
        let result: Result<(), std::fmt::Error> = Err(std::fmt::Error);
        assert!(result.is_err());
    }

    #[test]
    fn public_errors_are_send_sync_and_signatures_are_typed() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Error>();
        let _: fn(&str) -> Result<std::time::Duration> = crate::parse_duration;
        let _: fn(std::path::PathBuf) -> Result<crate::pcap::PcapWriter> =
            crate::pcap::PcapWriter::create;
    }
}
