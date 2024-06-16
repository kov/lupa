#![no_std]

pub const PATH_MAX: usize = 256;
pub const MAX_CPUS: usize = 1024;

#[repr(u64)]
pub enum EventKind {
    BeginOpen,
    FinishOpen,
    Close,
}

#[repr(C)]
pub struct FileEvent {
    pub id: u64,
    pub pid: u64,
    pub kind: EventKind,
    pub fd: i64,
    pub path: [u8; PATH_MAX],
}

impl FileEvent {
    fn for_pid(id: u64, pid: u64) -> Self {
        FileEvent {
            id,
            pid,
            fd: 0,
            kind: EventKind::Close,
            path: [0; PATH_MAX],
        }
    }

    pub fn begin_open(id: u64, pid: u64) -> Self {
        let mut event = FileEvent::for_pid(id, pid);
        event.kind = EventKind::BeginOpen;
        event
    }

    pub fn finish_open(id: u64, pid: u64, fd: i64) -> Self {
        let mut event = FileEvent::for_pid(id, pid);
        event.kind = EventKind::FinishOpen;
        event.fd = fd;
        event
    }

    pub fn close(id: u64, pid: u64, fd: i64) -> Self {
        let mut event = FileEvent::for_pid(id, pid);
        event.kind = EventKind::Close;
        event.fd = fd;
        event
    }
}
