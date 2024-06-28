use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::bail;
use clap::Command;

use crate::trace::{Event, EventDetail};

pub type EventList = Arc<Mutex<Vec<Event>>>;
pub type OpenFilesMap = Arc<Mutex<HashMap<(u64, i64), PathBuf>>>;

trait CloneableFnMut {
    fn call_mut(&mut self, shell: &mut Shell) -> Result<(), anyhow::Error>;
    fn clone_box(&self) -> Box<dyn CloneableFnMut>;
}

impl<F> CloneableFnMut for F
where
    F: FnMut(&mut Shell) -> Result<(), anyhow::Error> + Clone + 'static,
{
    fn call_mut(&mut self, shell: &mut Shell) -> Result<(), anyhow::Error> {
        self(shell)
    }

    fn clone_box(&self) -> Box<dyn CloneableFnMut> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn CloneableFnMut> {
    fn clone(&self) -> Box<dyn CloneableFnMut> {
        self.clone_box()
    }
}

struct Handler {
    command: Command,
    callback: Box<dyn CloneableFnMut>,
}

pub struct Shell {
    all_events: EventList,
    open_files: OpenFilesMap,

    commands: Vec<Handler>,
}

impl Shell {
    pub fn new(all_events: EventList, open_files: OpenFilesMap) -> Self {
        Shell {
            all_events,
            open_files,

            commands: vec![
                Handler {
                    command: Command::new("ls").about("List currently open files"),
                    callback: Box::new(Self::print_currently_open),
                },
                Handler {
                    command: Command::new("events").about("Show all events traced up to now"),
                    callback: Box::new(Self::print_all_events),
                },
                Handler {
                    command: Command::new("help").about("Print help for available commands"),
                    callback: Box::new(Self::print_help),
                },
                Handler {
                    command: Command::new("quit").about("Exit the program").alias("q"),
                    callback: Box::new(Self::quit),
                },
            ],
        }
    }

    pub fn handle_line(&mut self, line: String) -> Result<(), anyhow::Error> {
        let parts: Vec<&str> = line
            .split_ascii_whitespace()
            .skip_while(|s| s.is_empty())
            .collect();

        // There was nothing on the line.
        if parts.is_empty() {
            return Ok(());
        }

        let handler = self.commands.iter().find(|h| {
            h.command.get_name() == parts[0]
                || h.command
                    .get_all_aliases()
                    .find(|a| *a == parts[0])
                    .is_some()
        });

        if handler.is_none() {
            println!("unknown command");
            return Ok(());
        }

        let handler = handler.unwrap();
        let command_to_run = handler.command.clone();
        let mut callback = handler.callback.clone();

        match command_to_run.try_get_matches_from(parts) {
            Ok(_m) => callback.call_mut(self)?,
            Err(_) => return Ok(()),
        };

        Ok(())
    }

    fn print_help(&mut self) -> Result<(), anyhow::Error> {
        for cmd in self.commands.iter_mut() {
            println!(
                "{}\t{}",
                cmd.command.get_name(),
                cmd.command.get_about().unwrap_or_else(|| panic!(
                    "Help missing for command {}",
                    cmd.command.get_name()
                ))
            );
        }

        Ok(())
    }

    fn print_currently_open(&mut self) -> Result<(), anyhow::Error> {
        println!("PID\tFD\t\tPath");
        for ((pid, fd), path) in self.open_files.lock().unwrap().iter() {
            println!("{}\t{}\t\t{}", pid, fd, path.to_string_lossy());
        }

        Ok(())
    }

    fn print_all_events(&mut self) -> Result<(), anyhow::Error> {
        for event in self.all_events.lock().unwrap().iter() {
            match &event.detail {
                EventDetail::FileOpen { fd, path } => println!(
                    "[{}] Open fd {} from {}",
                    event.pid,
                    fd,
                    path.to_string_lossy()
                ),
                EventDetail::FailedFileOpen { errno, path } => println!(
                    "[{}] Error {} trying to open {}",
                    event.pid,
                    errno,
                    path.to_string_lossy()
                ),
                EventDetail::FdClose { fd } => println!("[{}] Close fd {}", event.pid, fd),
            }
        }

        Ok(())
    }

    fn quit(&mut self) -> Result<(), anyhow::Error> {
        bail!("Quit.")
    }
}
