use aya::{
    maps::{perf::PerfEventArrayBuffer, MapData, PerfEventArray},
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use log::trace;
use lupa_common::FileEvent;
use std::io;
use thiserror::Error;

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
            }
        }
        microsleep();
    }

    #[allow(unreachable_code)]
    Ok(())
}
