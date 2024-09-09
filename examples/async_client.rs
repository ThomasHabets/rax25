use std::io::Write;

use anyhow::Result;
use clap::Parser;
use tokio::io::AsyncReadExt;
use tokio_serial::SerialPortBuilderExt;

use rax25::r#async::Client;
use rax25::Addr;

#[derive(Parser, Debug)]
struct Opt {
    #[clap(short = 'p', default_value = "/dev/null")]
    port: String,

    #[clap(short = 's')]
    src: String,

    #[clap(short = 'r')]
    cr: bool,

    #[clap(short = 'e')]
    ext: bool,

    #[clap(short = 'v', default_value = "0")]
    v: usize,

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
    let port = tokio_serial::new(&opt.port, 9600).open_native_async()?;
    let mut stdin = tokio::io::stdin();
    let mut client =
        Client::connect(Addr::new("M0THC-1")?, Addr::new("M0THC-2")?, port, opt.ext).await?;
    println!("Connected");
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
                if buf ==  [101, 120, 105, 116, 10] {
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
