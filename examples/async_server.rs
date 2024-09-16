use anyhow::Result;
use clap::Parser;
use tokio_serial::SerialPortBuilderExt;

use rax25::r#async::ConnectionBuilder;
use rax25::Addr;

#[derive(Parser, Debug)]
struct Opt {
    #[clap(short = 'p', default_value = "/dev/null")]
    port: String,

    #[clap(short = 's')]
    src: String,

    #[clap(short = 'r')]
    cr: bool,

    #[clap(short = 'v', default_value = "0")]
    v: usize,

    #[clap(long)]
    capture: Option<std::path::PathBuf>,
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
    println!("Awaiting connection");
    let mut client = {
        let mut builder = ConnectionBuilder::new(Addr::new(&opt.src)?, port)?;
        if let Some(capture) = opt.capture {
            builder = builder.capture(capture);
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
