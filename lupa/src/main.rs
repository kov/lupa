#![feature(slice_split_once)]
use std::collections::HashMap;
use std::env;
use std::sync::mpsc::{self, Receiver, Sender};

use anyhow::bail;
use aya::maps::Array;
use aya::programs::{KProbe, TracePoint};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{debug, info, warn};
use tokio::signal;

use crate::trace::{Event, EventDetail};

mod trace;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        bail!("need a single argument, a PID to trace.");
    }

    let pid: u64 = args[1].parse()?;

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

    let (tx, rx): (Sender<Event>, Receiver<Event>) = mpsc::channel();
    let _ = std::thread::spawn(|| trace::run(bpf, tx));
    let _ = std::thread::spawn(move || {
        let mut currently_open = HashMap::<(u64, i64), Event>::new();
        loop {
            let event = rx.recv().unwrap();
            println!("Event received: {:?}", event);
            match event.detail {
                EventDetail::FileOpen { fd, .. } => {
                    if currently_open.insert((event.pid, fd), event).is_some() {
                        debug!("tried to insert duplicate fd {}", fd);
                    }
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
        }
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
