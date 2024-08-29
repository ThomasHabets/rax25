use anyhow::Result;
use clap::Parser;
use rax25::{Addr, Client, Kiss};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Parser, Debug)]
struct Opt {
    #[clap(short = 'p', default_value = "/dev/null")]
    port: String,
}

fn main() -> Result<()> {
    let opt = Opt::parse();
    let done = Arc::new(AtomicBool::new(false));
    stderrlog::new()
        .module("rax25")
        .verbosity(0)
        .init()
        .unwrap();
    let k = Kiss::new(&opt.port)?;
    let mut c = Client::new(Addr::new("M0THC-1")?, Box::new(k));

    let d = done.clone();
    ctrlc::set_handler(move || {
        println!("Received SIGINT signal, shutting down...");
        d.store(true, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    eprintln!("==== CONNECTING");
    c.connect(&Addr::new("M0THC-2")?)?;
    eprintln!("==== WRITING");
    c.write("echo hello world".as_bytes())?;
    while !done.load(Ordering::SeqCst) {
        if let Ok(Some(data)) = c.read_until(done.clone()) {
            // eprintln!("====> {data:?}");
            println!("{}", String::from_utf8(data)?);
        }
    }
    Ok(())
}
