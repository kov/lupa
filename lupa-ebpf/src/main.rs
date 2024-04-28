#![no_std]
#![no_main]

use aya_ebpf::{macros::kretprobe, programs::ProbeContext};
use aya_log_ebpf::info;

#[kretprobe]
pub fn do_sys_openat2(ctx: ProbeContext) -> u32 {
    match try_do_sys_openat2(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_do_sys_openat2(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function do_sys_openat2 called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
