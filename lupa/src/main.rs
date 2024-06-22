#![feature(slice_split_once)]
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

use anyhow::bail;
use log::debug;
use rustyline::error::ReadlineError;

use crate::trace::{init_ebpf, Event, EventDetail};

mod trace;

type EventList = Arc<Mutex<Vec<Event>>>;
type OpenFilesMap = Arc<Mutex<HashMap<(u64, i64), PathBuf>>>;

fn begin_tracking_events(rx: Receiver<Event>, all_events: EventList, currently_open: OpenFilesMap) {
    let _ = std::thread::spawn(move || loop {
        let event = rx.recv().unwrap();
        println!("Event received: {:?}", event);

        match event.detail {
            EventDetail::FileOpen { fd, ref path } => {
                if currently_open
                    .lock()
                    .unwrap()
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
                if currently_open
                    .lock()
                    .unwrap()
                    .remove_entry(&(event.pid, fd))
                    .is_none()
                {
                    debug!(
                        "no fd on hashmap while trying to close fd {} event {:?}",
                        fd, event
                    );
                }
            }
        }

        all_events.lock().unwrap().push(event);
    });
}

fn print_help() {
    println!("help\nshow this help text");
    println!("lsof\nshow currently open files");
    println!("q\nexit the program");
}

fn print_currently_open(currently_open: OpenFilesMap) {
    println!("PID\tFD\t\tPath");
    for ((pid, fd), path) in currently_open.lock().unwrap().iter() {
        println!("{}\t{}\t\t{}", pid, fd, path.to_string_lossy());
    }
}

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

    begin_tracking_events(rx, all_events.clone(), currently_open.clone());

    let mut rl = rustyline::DefaultEditor::new()?;
    loop {
        match rl.readline(">> ") {
            Ok(line) => match line.trim() {
                "q" => break,
                "help" => print_help(),
                "lsof" => print_currently_open(currently_open.clone()),
                _ => println!("unknown command"),
            },
            Err(ReadlineError::Eof) => break,
            Err(_) => println!("No input"),
        }
    }

    Ok(())
}
