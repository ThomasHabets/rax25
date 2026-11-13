//! Frame-aware KISS loss proxy, between one application and a modem.
use anyhow::{Result, bail};
use clap::Parser;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use rax25::pcapng::{Direction, PcapNgWriter};
use std::{
    fs::File,
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Parser)]
struct Opt {
    /// TCP address on which to accept one KISS application.
    #[arg(long)]
    listen: String,
    /// Modem endpoint: `tcp://host:port` or `serial:///dev/ttyUSB0`.
    #[arg(long)]
    modem: String,
    /// Percentage of application-to-modem data frames to drop (0..=100).
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=100))]
    tx_drop: u8,
    /// Percentage of modem-to-application data frames to drop (0..=100).
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=100))]
    rx_drop: u8,
    /// RNG seed; omitted seeds are randomly generated and printed.
    #[arg(long)]
    seed: Option<u64>,
    /// New pcapng file recording forwarded and dropped AX.25 frames.
    #[arg(long)]
    capture: Option<std::path::PathBuf>,
}

type Capture = Arc<Mutex<Option<PcapNgWriter<File>>>>;

async fn forward(
    mut input: impl AsyncRead + Unpin,
    mut output: impl AsyncWrite + Unpin,
    percent: u8,
    mut rng: StdRng,
    direction: Direction,
    capture: Capture,
) -> Result<()> {
    let mut frame = Vec::new();
    let mut active = false;
    let mut buffer = [0; 4096];
    loop {
        let count = input.read(&mut buffer).await?;
        if count == 0 {
            if !frame.is_empty() {
                bail!("truncated KISS frame");
            }
            output.shutdown().await?;
            return Ok(());
        }
        for &byte in &buffer[..count] {
            if byte == 0xc0 {
                if !frame.is_empty() {
                    let decoded = rax25::unescape(&frame)?;
                    let data = decoded[0].trailing_zeros() >= 4;
                    let dropped = data && rng.random_range(0_u8..100) < percent;
                    if data
                        && let Some(writer) = &mut *capture
                            .lock()
                            .map_err(|_| anyhow::anyhow!("capture lock poisoned"))?
                    {
                        writer.write(&decoded[1..], direction, dropped)?;
                    }
                    if !dropped {
                        output.write_all(&[0xc0]).await?;
                        output.write_all(&frame).await?;
                        output.write_all(&[0xc0]).await?;
                    }
                    frame.clear();
                }
                active = true;
            } else if active {
                frame.push(byte);
                if frame.len() > 131_072 {
                    bail!("oversized KISS frame");
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    let seed = opt.seed.unwrap_or_else(rand::random);
    eprintln!("KISS loss seed: {seed}");
    let mut master = StdRng::seed_from_u64(seed);
    let tx = StdRng::seed_from_u64(master.random());
    let rx = StdRng::seed_from_u64(master.random());
    let capture = Arc::new(Mutex::new(
        opt.capture
            .map(|path| PcapNgWriter::new(File::options().write(true).create_new(true).open(path)?))
            .transpose()?,
    ));
    let listener = tokio::net::TcpListener::bind(&opt.listen).await?;
    let (application, _) = listener.accept().await?;
    // Allow the modem process to start alongside the proxy. Do not probe it:
    // some KISS modems accept only one application connection.
    let modem = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            match rax25::r#async::connect_kiss_endpoint(&opt.modem).await {
                Err(rax25::Error::Endpoint { source: error, .. })
                    if error.kind() == std::io::ErrorKind::ConnectionRefused =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                result => break result,
            }
        }
    })
    .await??;
    let (ar, aw) = tokio::io::split(application);
    let (mr, mw) = tokio::io::split(modem);
    tokio::try_join!(
        forward(ar, mw, opt.tx_drop, tx, Direction::Tx, capture.clone()),
        forward(mr, aw, opt.rx_drop, rx, Direction::Rx, capture),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run(percent: u8, seed: u64) -> Result<Vec<u8>> {
        // Shared delimiters, idle delimiters, escaped data, nonzero KISS port,
        // and a control command which must survive even 100% data loss.
        let input = [
            0xc0, 0xc0, 0x10, 0xdb, 0xdc, 0xc0, 0x01, 7, 0xc0, 0x00, 42, 0xc0,
        ];
        let mut output = Vec::new();
        forward(
            &input[..],
            &mut output,
            percent,
            StdRng::seed_from_u64(seed),
            Direction::Tx,
            Arc::new(Mutex::new(None)),
        )
        .await?;
        Ok(output)
    }

    #[tokio::test]
    async fn loss_extremes_and_seed_replay() -> Result<()> {
        assert_eq!(run(100, 42).await?, [0xc0, 1, 7, 0xc0]);
        assert_eq!(
            run(0, 42).await?,
            [
                0xc0, 0x10, 0xdb, 0xdc, 0xc0, 0xc0, 1, 7, 0xc0, 0xc0, 0, 42, 0xc0
            ]
        );
        assert_eq!(run(50, 123).await?, run(50, 123).await?);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_truncated_frames() {
        let mut output = Vec::new();
        assert!(
            forward(
                &[0xc0, 0, 1][..],
                &mut output,
                0,
                StdRng::seed_from_u64(1),
                Direction::Rx,
                Arc::new(Mutex::new(None))
            )
            .await
            .is_err()
        );
    }
}
