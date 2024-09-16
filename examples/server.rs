//! Example server using the synchronous API.
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use clap::Parser;
use log::debug;

use rax25::sync::Client;
use rax25::{Addr, BusHub, BusKiss};

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
}

fn main() -> Result<()> {
    let opt = Opt::parse();
    let done = Arc::new(AtomicBool::new(false));
    stderrlog::new()
        .module("rax25")
        .verbosity(opt.v)
        .init()
        .unwrap();
    let bus = Arc::new(Mutex::new(bus::Bus::<rax25::BusMessage>::new(10)));
    let mut bk = BusKiss::new(&opt.port, bus.clone())?;
    std::thread::spawn(move || {
        bk.run();
    });
    let k = BusHub::new(bus);
    let mut listener = Client::new(Addr::new(&opt.src)?, Box::new(k));

    let d = done.clone();
    ctrlc::set_handler(move || {
        println!("Received SIGINT signal, shutting down...");
        d.store(true, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    eprintln!("==== Awaiting connection");
    let mut c = listener
        .accept(std::time::Instant::now() + std::time::Duration::from_secs(60))?
        .expect("connection timeout");
    drop(listener);
    eprintln!("==== Connected");
    c.write("You are connected!\n".as_bytes())?; // TODO: cr
    while !done.load(Ordering::SeqCst) && !c.eof() {
        match c.read_until(done.clone()) {
            Ok(Some(data)) => {
                // eprintln!("====> {data:?}");
                let s = match String::from_utf8(data.clone()) {
                    Ok(s) => s,
                    Err(_) => String::from_utf8(data.iter().map(|&b| b & 0x7F).collect())?,
                };
                println!("Got data: {s}");
                std::io::stdout().flush()?;
                let reply = format!("Got <{s}>\n");
                let reply = if opt.cr {
                    reply.replace("\r", "\n")
                } else {
                    reply
                };
                c.write(reply.as_bytes())?;
            }
            Ok(None) => break,
            Err(e) => {
                if false {
                    // probably timeout
                    debug!("Error reading: {e:?}");
                }
            }
        }
    }
    eprintln!("Main loop exit");

    // TODO: wait only until the outgoing packets have all been
    // sent, namely UA.
    std::thread::sleep(std::time::Duration::from_secs(1));
    done.store(true, Ordering::SeqCst);
    Ok(())
}
