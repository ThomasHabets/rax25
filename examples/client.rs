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
    let k = Kiss::new(&opt.port)?;
    let mut c = Client::new(Addr::new("M0THC-1"), Box::new(k));
    c.connect(&Addr::new("M0THC-2"))?;
    c.write(&vec![1, 2, 3])?;
    Ok(())
}
