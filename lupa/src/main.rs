#![feature(slice_split_once)]
#![feature(fn_traits)]
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

use anyhow::bail;
use cli::Shell;
use log::debug;
use rustyline::error::ReadlineError;
use rustyline::ExternalPrinter;

use crate::cli::{EventList, OpenFilesMap};
use crate::trace::{init_ebpf, Event, EventDetail};

mod cli;
mod trace;

fn begin_tracking_events<W: ExternalPrinter + Send + 'static>(
    rx: Receiver<Event>,
    mut writer: W,
    all_events: EventList,
    currently_open: OpenFilesMap,
) {
    let _ = std::thread::spawn(move || loop {
        let event = rx.recv().unwrap();

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
                writer
                    .print(format!(
                        "Process {} opened fd {} with path {}",
                        event.pid,
                        fd,
                        path.to_string_lossy(),
                    ))
                    .expect("Failed to write to terminal");
            }
            EventDetail::FailedFileOpen { errno, ref path } => {
                debug!(
                    "attempt to open file path {:?} failed with error {}",
                    path, errno
                );
                writer
                    .print(format!(
                        "Process {} failed to open path {} with error {}",
                        event.pid,
                        path.to_string_lossy(),
                        errno
                    ))
                    .expect("Failed to write to terminal");
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
                writer
                    .print(format!("Process {} closed fd {}", event.pid, fd,))
                    .expect("Failed to write to terminal");
            }
        }

        all_events.lock().unwrap().push(event);
    });
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

    let mut rl = rustyline::DefaultEditor::new()?;
    let writer = rl.create_external_printer()?;

    begin_tracking_events(rx, writer, all_events.clone(), currently_open.clone());

    // CLI
    let mut shell = Shell::new(all_events, currently_open);
    loop {
        match rl.readline(">> ") {
            Ok(line) => {
                if shell.handle_line(line).is_err() {
                    break;
                };
            }
            Err(ReadlineError::Eof) => break,
            Err(_) => println!("No input"),
        }
    }

    Ok(())
}
