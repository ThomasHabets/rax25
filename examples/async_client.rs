use std::io::Write;

use anyhow::Result;
use clap::Parser;
use log::info;
use tokio::io::AsyncReadExt;

use rax25::{
    Addr,
    r#async::{ConnectionBuilder, connect_kiss_endpoint},
    parse_duration,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Parser, Debug)]
struct Opt {
    #[allow(clippy::doc_markdown)]
    /// KISS endpoint, such as serial:///dev/rfcomm0 or tcp://localhost:8000.
    #[clap(short = 'p', default_value = "serial:///dev/null")]
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
    #[clap(short = 'v', default_value = "info")]
    v: LogLevel,

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

    /// Experiments to enable.
    #[clap(long, value_enum, value_delimiter = ',')]
    experiments: Vec<rax25::Experiment>,

    /// Destination callsign and SSID.
    #[clap()]
    dst: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    stderrlog::new()
        .module("rax25")
        .verbosity(opt.v as usize)
        .show_module_names(true)
        .init()
        .unwrap();
    let port = connect_kiss_endpoint(&opt.port).await?;
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
        for ex in &opt.experiments {
            builder = builder.enable_experiment(*ex);
        }
        builder
    };

    let st = std::time::Instant::now();
    let mut client = builder.connect(Addr::new(&opt.dst)?).await?;
    info!("Connected after {:?}", st.elapsed());
    let mut sigint = {
        use tokio::signal::unix::{SignalKind, signal};
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
                let s = if opt.cr { s.replace('\r', "\n") } else {s};
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
