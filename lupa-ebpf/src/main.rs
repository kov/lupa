#![no_std]
#![no_main]

use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::macros::map;
use aya_ebpf::maps::Array;
use aya_ebpf::programs::TracePointContext;
use aya_ebpf::{
    macros::{kretprobe, tracepoint},
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[map]
static PID_TO_TRACE: Array<u64> = Array::with_max_entries(1, 0);

fn getpid() -> u64 {
    bpf_get_current_pid_tgid() >> 32
}

fn should_trace(pid: u64) -> bool {
    let to_track = match PID_TO_TRACE.get(0) {
        None => return false,
        Some(to_track) => *to_track,
    };

    pid == to_track
}

#[kretprobe]
pub fn do_sys_openat2(ctx: ProbeContext) -> u32 {
    match try_do_sys_openat2(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_do_sys_openat2(ctx: ProbeContext) -> Result<u32, u32> {
    let pid = getpid();

    if !should_trace(pid) {
        return Ok(0);
    }

    let fd: i64 = ctx.ret().ok_or(1u32)?;

    if fd < 0 {
        info!(&ctx, "PID {} failed to open file", pid)
    } else {
        info!(&ctx, "function do_sys_openat2 called PID {} FD {}", pid, fd);
    }

    Ok(0)
}

/*
 * /sys/kernel/debug/tracing/events/syscalls/sys_enter_close/format
 *
 * name: sys_enter_close
 * ID: 577
 * format:
 *     field:unsigned short common_type;	offset:0;	size:2;	signed:0;
 *     field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
 *     field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
 *     field:int common_pid;	offset:4;	size:4;	signed:1;
 *
 *     field:int __syscall_nr;	offset:8;	size:4;	signed:1;
 *     field:unsigned int fd;	offset:16;	size:8;	signed:0;
 *
 * print fmt: "fd: 0x%08lx", ((unsigned long)(REC->fd))
 */
static SYS_CLOSE_FD_OFFSET: usize = 16;

#[tracepoint]
pub fn do_sys_enter_close(ctx: TracePointContext) {
    let pid = getpid();

    if !should_trace(pid) {
        return;
    }

    let fd: u64 = unsafe {
        match ctx.read_at(SYS_CLOSE_FD_OFFSET) {
            Ok(fd) => fd,
            Err(e) => {
                info!(&ctx, "failed to read: {}", e);
                0
            }
        }
    };

    info!(
        &ctx,
        "function do_sys_enter_close called PID {} FD {}", pid, fd
    );
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
