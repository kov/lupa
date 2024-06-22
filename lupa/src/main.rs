#![feature(slice_split_once)]
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

use anyhow::bail;
use log::{debug, info};
use tokio::signal;

use crate::trace::{init_ebpf, Event, EventDetail};

mod trace;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        bail!("need a single argument, a PID to trace.");
    }

    let pid: u64 = args[1].parse()?;

    let bpf = init_ebpf(pid)?;

    let (tx, rx): (Sender<Event>, Receiver<Event>) = mpsc::channel();
    let _ = std::thread::spawn(|| trace::run(bpf, tx));

    let all_events = Arc::new(Mutex::new(vec![]));
    let currently_open = Arc::new(Mutex::new(HashMap::<(u64, i64), PathBuf>::new()));

    let t_all_events = all_events.clone();
    let t_currently_open = currently_open.clone();
    let _ = std::thread::spawn(move || loop {
        let event = rx.recv().unwrap();
        println!("Event received: {:?}", event);

        let mut currently_open = t_currently_open.lock().unwrap();
        match event.detail {
            EventDetail::FileOpen { fd, ref path } => {
                if currently_open
                    .insert((event.pid, fd), path.clone())
                    .is_some()
                {
                    debug!("tried to insert duplicate fd {}", fd);
                }
            }
            EventDetail::FailedFileOpen { errno, ref path } => {
                debug!(
                    "attempt to open file path {:?} failed with error {}",
                    path, errno
                );
            }
            EventDetail::FdClose { fd } => {
                if currently_open.remove_entry(&(event.pid, fd)).is_none() {
                    debug!(
                        "no fd on hashmap while trying to close fd {} event {:?}",
                        fd, event
                    );
                }
            }
        }
        drop(currently_open);

        t_all_events.lock().unwrap().push(event);
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("\nCurrently open:");
    println!("{:?}", currently_open.lock().unwrap());
    println!("\nAll events:");
    println!("{:?}", all_events.lock().unwrap());
    info!("Exiting...");

    Ok(())
}
