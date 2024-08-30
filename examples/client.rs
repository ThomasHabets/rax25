use anyhow::Result;
use clap::Parser;
use rax25::{Addr, Client, Kiss};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Parser, Debug)]
struct Opt {
    #[clap(short = 'p', default_value = "/dev/null")]
    port: String,

    #[clap(short = 'r')]
    cr: bool,
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

    let (tx, rx) = std::sync::mpsc::channel();

    let d = done.clone();
    let cr = opt.cr;
    std::thread::spawn(move || {
        use std::io::BufRead;
        while !d.load(Ordering::SeqCst) {
            let stdin = std::io::stdin();
            let mut iterator = stdin.lock().lines();
            if let Some(line) = iterator.next() {
                if cr {
                    tx.send(line.and_then(|s| Ok(s.trim_end().to_owned() + "\r")))
                        .unwrap();
                } else {
                    tx.send(line).unwrap();
                }
            }
        }
    });

    eprintln!("==== CONNECTING");
    c.connect(&Addr::new("M0THC-2")?)?;
    //eprintln!("==== WRITING");
    //c.write("echo hello world".as_bytes())?;
    while !done.load(Ordering::SeqCst) {
        if let Ok(Some(data)) = c.read_until(done.clone()) {
            // eprintln!("====> {data:?}");
            println!("{}", String::from_utf8(data)?);
        }
        match rx.recv_timeout(std::time::Duration::from_secs(0)) {
            Ok(Ok(line)) => c.write(&line.as_bytes())?,
            Ok(Err(e)) => eprintln!("Error reading line: {}", e),
            Err(_) => {}
        };
    }
    Ok(())
}
