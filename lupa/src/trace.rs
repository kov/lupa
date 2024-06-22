use std::{
    collections::HashMap, ffi::OsStr, io, os::unix::ffi::OsStrExt, path::PathBuf,
    sync::mpsc::Sender,
};

use aya::maps::Array;
use aya::programs::{KProbe, TracePoint};
use aya::{include_bytes_aligned, Bpf};
use aya::{
    maps::{perf::PerfEventArrayBuffer, MapData, PerfEventArray},
    util::online_cpus,
};
use aya_log::BpfLogger;
use bytes::BytesMut;
use log::trace;
use log::{debug, warn};
use lupa_common::{EventKind, FileEvent};
use thiserror::Error;

#[derive(Debug)]
pub enum EventDetail {
    FileOpen { fd: i64, path: PathBuf },
    FailedFileOpen { errno: i64, path: PathBuf },
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
        let path = PathBuf::from(OsStr::from_bytes(path));

        if finish.fd < 0 {
            Event {
                pid: begin.pid,
                detail: EventDetail::FailedFileOpen {
                    errno: finish.fd,
                    path,
                },
            }
        } else {
            Event {
                pid: begin.pid,
                detail: EventDetail::FileOpen {
                    fd: finish.fd,
                    path,
                },
            }
        }
    }

    fn from_close_event(event: &FileEvent) -> Self {
        Event {
            pid: event.pid,
            detail: EventDetail::FdClose { fd: event.fd },
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

pub fn run(mut bpf: Bpf, tx: Sender<Event>) -> Result<(), anyhow::Error> {
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
                            tx.send(api_event).unwrap();
                        } else {
                            trace!(
                                "no inflight event was found with id {} pid {} path {:?}",
                                event.id,
                                event.pid,
                                event.path
                            );
                        }
                    }
                    EventKind::Close => {
                        let api_event = Event::from_close_event(&event);
                        tx.send(api_event).unwrap();
                    }
                }
            }
        }
        microsleep();
    }

    #[allow(unreachable_code)]
    Ok(())
}

pub fn init_ebpf(pid: u64) -> Result<Bpf, anyhow::Error> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/lupa"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/lupa"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let mut pid_to_trace: Array<_, u64> = bpf
        .take_map("PID_TO_TRACE")
        .expect("Failed to obtain PID to track map from probe")
        .try_into()
        .unwrap();
    pid_to_trace
        .set(0, pid, 0)
        .expect("Failed to set PID on the probe's map");

    let program: &mut KProbe = bpf.program_mut("do_sys_openat2_exit").unwrap().try_into()?;
    program.load()?;
    program.attach("do_sys_openat2", 0)?;

    let program: &mut KProbe = bpf
        .program_mut("do_sys_openat2_entry")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("do_sys_openat2", 0)?;

    let program: &mut TracePoint = bpf.program_mut("do_sys_enter_close").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_close")?;

    Ok(bpf)
}
