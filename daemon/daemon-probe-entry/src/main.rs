#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod binding;

use crate::binding::{sock, sock_common};

use aya_ebpf::{helpers::bpf_probe_read_kernel, macros::kretprobe, programs::ProbeContext};
use aya_log_ebpf::info;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[kretprobe]
pub fn kprobetcp(ctx: ProbeContext) -> u32 {
    match try_kprobetcp(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn try_kprobetcp(ctx: ProbeContext) -> Result<u32, i64> {
    let sock: *mut sock = ctx.arg(1).ok_or(1i64)?;
    let ret: i32 = ctx.ret().ok_or(-233)?;
    let sk_common = unsafe {
        bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common).map_err(|e| e)?
    };

    match sk_common.skc_family {
        AF_INET => {
            let src_addr =
                u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr });
            let dest_addr: u32 =
                u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr });
            let raw_skc_dport: u16 =
                u16::from_be(unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport });
            let raw_skc_num: u16 =
                u16::from_be(unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_num });
            info!(
                &ctx,
                "AF_INET src address: {:i}, dest address: {:i}, skc_dport: {}, skc_num: {}, return code is: {}",
                src_addr,
                dest_addr,
                raw_skc_dport,
                raw_skc_num,
                ret
            );
            Ok(0)
        }
        // AF_INET6 => {
        //     let src_addr = sk_common.skc_v6_rcv_saddr;
        //     let dest_addr = sk_common.skc_v6_daddr;
        //     info!(
        //         &ctx,
        //         "AF_INET6 src addr: {:i}, dest addr: {:i}",
        //         unsafe { src_addr.in6_u.u6_addr8 },
        //         unsafe { dest_addr.in6_u.u6_addr8 }
        //     );
        //     Ok(0)
        // }
        _ => Ok(0),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
