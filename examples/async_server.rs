use anyhow::Result;
use clap::Parser;
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
    println!("Awaiting connection");
    let mut client = {
        let mut builder = ConnectionBuilder::new(Addr::new(&opt.src)?, port)?;
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
        builder.accept().await?
    };
    println!("Connected");
    client.write(b"Welcome to the server!\n").await?;
    loop {
        tokio::select! {
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
                let s = s.trim_end();
                client.write(format!("Got <{s}>\n").as_bytes()).await?;
            },
        }
    }
    eprintln!("End of main loop");
    client.disconnect().await?;
    Ok(())
}
