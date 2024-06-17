use aya::{
    maps::{perf::PerfEventArrayBuffer, MapData, PerfEventArray},
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use log::trace;
use lupa_common::{EventKind, FileEvent};
use std::{collections::HashMap, ffi::OsStr, io, os::unix::ffi::OsStrExt, path::PathBuf};
use thiserror::Error;

#[derive(Debug)]
pub enum EventDetail {
    FileOpen { fd: i64, path: PathBuf },
    FdClose { fd: i64 },
}

#[derive(Debug)]
pub struct Event {
    pub pid: u64,
    pub detail: EventDetail,
}

impl Event {
    fn from_open_events(begin: &FileEvent, finish: &FileEvent) -> Self {
        assert_eq!(begin.id, finish.id);

        // Remove the trailing \0s, so they do not end up becoming part of the name.
        let path = match begin.path.split_once(|x| *x == b'\0') {
            Some((p, _)) => p,
            None => &begin.path,
        };

        Event {
            pid: begin.pid,
            detail: EventDetail::FileOpen {
                fd: finish.fd,
                path: PathBuf::from(OsStr::from_bytes(path)),
            },
        }
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid /sys/devices/system/cpu/online format")]
    InvalidOnlineCpu(#[source] io::Error),
}

#[inline]
fn microsleep() {
    std::thread::sleep(std::time::Duration::from_millis(10));
}

fn read_event(buf: &mut PerfEventArrayBuffer<MapData>) -> FileEvent {
    let mut buffers = vec![BytesMut::with_capacity(std::mem::size_of::<FileEvent>()); 1];

    let events = buf.read_events(&mut buffers).unwrap();
    assert_eq!(events.read, 1);

    // Safety: the struct used here is shared between both sides. If
    // a read succeeds, that is the only thing that can be there.
    unsafe { std::ptr::read(buffers[0].as_ptr() as *const FileEvent) }
}

pub fn run(mut bpf: Bpf) -> Result<(), anyhow::Error> {
    let mut events: PerfEventArray<_> = bpf
        .take_map("FILE_EVENTS")
        .expect("Failed to take file events map")
        .try_into()?;

    let mut buffers = vec![];
    for cpu_id in online_cpus().map_err(Error::InvalidOnlineCpu)? {
        buffers.push(events.open(cpu_id, None)?);
    }

    let mut inflight_map = HashMap::<u64, FileEvent>::new();
    loop {
        for buf in &mut buffers {
            if buf.readable() {
                let event: FileEvent = read_event(buf);
                trace!(
                    "event: id {} pid {} fd {} {:?}",
                    event.id,
                    event.pid,
                    event.fd,
                    event.path
                );
                match event.kind {
                    EventKind::BeginOpen => {
                        if let Some(prev_event) = inflight_map.insert(event.id, event) {
                            trace!(
                                "inflight event with id {} pid {} path {:?} removed unresolved",
                                prev_event.id,
                                prev_event.pid,
                                prev_event.path
                            );
                        }
                    }
                    EventKind::FinishOpen => {
                        if let Some((_, prev_event)) = inflight_map.remove_entry(&event.id) {
                            let api_event = Event::from_open_events(&prev_event, &event);
                            println!("file opened: {:?}", api_event);
                        } else {
                            trace!(
                                "no inflight event was found with id {} pid {} path {:?}",
                                event.id,
                                event.pid,
                                event.path
                            );
                        }
                    }
                    EventKind::Close => unimplemented!(),
                }
            }
        }
        microsleep();
    }

    #[allow(unreachable_code)]
    Ok(())
}
