use anyhow::Result;
use clap::Parser;
use rax25::{Addr, Client, Kiss};

#[derive(Parser, Debug)]
struct Opt {
    #[clap(short = 'p', default_value = "/dev/null")]
    port: String,
}

fn main() -> Result<()> {
    let opt = Opt::parse();
    stderrlog::new()
        .module("rax25")
        .verbosity(0)
        .init()
        .unwrap();
    let k = Kiss::new(&opt.port)?;
    let mut c = Client::new(Addr::new("M0THC-1")?, Box::new(k));
    eprintln!("==== CONNECTING");
    c.connect(&Addr::new("M0THC-2")?)?;
    eprintln!("==== WRITING");
    c.write("echo hello world".as_bytes())?;
    loop {
        if let Ok(data) = c.read() {
            // eprintln!("====> {data:?}");
            println!("{}", String::from_utf8(data)?);
        }
    }
}
