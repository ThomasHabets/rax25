use std::io::Write;

use anyhow::Result;
use clap::Parser;
use tokio::io::AsyncReadExt;
use tokio_serial::SerialPortBuilderExt;

use rax25::r#async::{ConnectionBuilder, PortType};
use rax25::{parse_duration, Addr};

#[derive(Parser, Debug)]
struct Opt {
    /// KISS serial port.
    #[clap(short = 'p', default_value = "/dev/null")]
    port: String,

    /// Source callsign and SSID.
    #[clap(short = 's')]
    src: String,

    /// Use CR instead of NL.
    #[clap(short = 'r')]
    cr: bool,

    /// Use mod-128 extended AX.25.
    #[clap(short = 'e')]
    ext: bool,

    /// Verbosity level.
    #[clap(short = 'v', default_value = "0")]
    v: usize,

    /// Capture packets in/out to pcap.
    #[clap(long)]
    capture: Option<std::path::PathBuf>,

    /// Initial SRT value.
    #[clap(long, value_parser = parse_duration)]
    srt: Option<std::time::Duration>,

    /// T3 (idle timer) value.
    #[clap(long, value_parser = parse_duration)]
    t3v: Option<std::time::Duration>,

    /// MTU for outgoing frames.
    #[clap(long)]
    mtu: Option<usize>,

    /// Destination callsign and SSID.
    #[clap()]
    dst: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    stderrlog::new()
        .module("rax25")
        .verbosity(opt.v)
        .init()
        .unwrap();
    let port = if opt.port.contains('/') {
        PortType::Serial(tokio_serial::new(&opt.port, 9600).open_native_async()?)
    } else {
        PortType::Tcp(tokio::net::TcpStream::connect(&opt.port).await?)
    };
    let mut stdin = tokio::io::stdin();
    let builder = {
        let mut builder = ConnectionBuilder::new(Addr::new(&opt.src)?, port)?;
        if opt.ext {
            builder = builder.extended(Some(opt.ext));
        }
        if let Some(capture) = opt.capture {
            builder = builder.capture(capture);
        }
        if let Some(v) = opt.srt {
            builder = builder.srt_default(v);
        }
        if let Some(v) = opt.t3v {
            builder = builder.t3v(v);
        }
        if let Some(v) = opt.mtu {
            builder = builder.mtu(v);
        }
        builder
    };

    let st = std::time::Instant::now();
    let mut client = builder.connect(Addr::new(&opt.dst)?).await?;
    println!("Connected after {:?}", std::time::Instant::now() - st);
    let mut sigint = {
        use tokio::signal::unix::{signal, SignalKind};
        signal(SignalKind::interrupt())?
    };
    loop {
        let mut buf = [0; 1024];
        tokio::select! {
            _ = sigint.recv() => {
                eprintln!("Sigint received");
                break;
            },
            res = stdin.read(&mut buf) => {
                let res = res?;
                if res == 0 {
                    eprintln!("Got EOF from stdin");
                    break;
                }
                let buf = &buf[..res];
                if buf ==  b"exit\n" {
                    eprintln!("Got 'exit' from user");
                    break;
                }
                let buf: Vec<_> = if opt.cr {
                    buf.iter().map(|&b| if b == b'\n' { b'\r' } else {b}).collect()
                } else {
                    buf.to_vec()
                };
                //eprintln!("Got {buf:?} from stdin");
                client.write(&buf).await?;
            },
            data = client.read() => {
                let data = data?;
                if data.is_empty() {
                    eprintln!("Got EOF");
                    break;
                }
                let s = match String::from_utf8(data.clone()) {
                    Ok(s) => s,
                    Err(_) => String::from_utf8(data.iter().map(|&b| b & 0x7F).collect())?,
                };
                let s = if opt.cr { s.replace("\r", "\n") } else {s};
                print!("{s}");
                std::io::stdout().flush()?;
            },
        }
    }
    eprintln!("End of main loop");
    client.disconnect().await?;
    eprintln!("Disconnected");
    Ok(())
}
