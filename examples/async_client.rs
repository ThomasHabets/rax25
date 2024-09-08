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
    loop {
        let mut buf = [0; 1024];
        tokio::select! {
            res = stdin.read(&mut buf) => {
                let buf = &buf[..res?];
                if buf ==  [101, 120, 105, 116, 10] {
                    break;
                }
                //eprintln!("Got {buf:?} from stdin");
                client.write(buf).await?;
            },
            data = client.read() => {
                let data = data?;
                if data.is_empty() {
                    println!("Got EOF");
                    break;
                }
                let s = match String::from_utf8(data.clone()) {
                    Ok(s) => s,
                    Err(_) => String::from_utf8(data.iter().map(|&b| b & 0x7F).collect())?,
                };
                print!("{s}");
                std::io::stdout().flush()?;
            },
        }
    }
    Ok(())
}
