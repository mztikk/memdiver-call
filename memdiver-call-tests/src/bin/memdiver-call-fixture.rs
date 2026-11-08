//! Test fixture for `memdiver-call`.
//!
//! The process prints a `READY` line with its PID and the addresses of the
//! functions the tests call, then blocks on standard input. `PING` is answered
//! with `PONG` so a test can prove the target survived and resumed.

use std::io::{self, Write};
use std::sync::atomic::AtomicU64;
use std::time::Duration;

/// Counter incremented by the frame-loop tick used by the Wine tests.
static TICK: AtomicU64 = AtomicU64::new(0);

/// 64-bit scratch buffer written by `fixture_store` and read by the parent.
///
/// The fixture never touches it anywhere else, so the parent can read it
/// without a race outside a call.
static BUFFER: AtomicU64 = AtomicU64::new(0);

/// Data export used to prove `call_export` rejects non-executable exports.
#[unsafe(no_mangle)]
pub static FIXTURE_DATA: u64 = 0x1234_5678_9ABC_DEF0;

/// Value returned by `fixture_ping`.
const PING_VALUE: u64 = 0x5049_4E47; // "PING"

/// Adds two 64-bit integers.
#[cfg(target_pointer_width = "64")]
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn fixture_add(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}

/// Adds two 32-bit integers (32-bit targets).
#[cfg(target_pointer_width = "32")]
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn fixture_add(a: u32, b: u32) -> u64 {
    u64::from(a.wrapping_add(b))
}

/// Combines six 64-bit arguments with distinct weights.
#[cfg(target_pointer_width = "64")]
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn fixture_mix(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u64 {
    a.wrapping_add(b.wrapping_mul(2))
        .wrapping_add(c.wrapping_mul(3))
        .wrapping_add(d.wrapping_mul(4))
        .wrapping_add(e.wrapping_mul(5))
        .wrapping_add(f.wrapping_mul(6))
}

/// Combines six 32-bit arguments with distinct weights (32-bit targets).
#[cfg(target_pointer_width = "32")]
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn fixture_mix(a: u32, b: u32, c: u32, d: u32, e: u32, f: u32) -> u64 {
    u64::from(
        a.wrapping_add(b.wrapping_mul(2))
            .wrapping_add(c.wrapping_mul(3))
            .wrapping_add(d.wrapping_mul(4))
            .wrapping_add(e.wrapping_mul(5))
            .wrapping_add(f.wrapping_mul(6)),
    )
}

/// Writes `value` to `pointer`, which the parent passes as a raw target
/// address.
#[cfg(target_pointer_width = "64")]
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn fixture_store(pointer: u64, value: u64) {
    // SAFETY: the parent passes the address of `BUFFER`, an 8-byte-aligned
    // static in this process, as printed in the READY line.
    unsafe {
        std::ptr::write_unaligned(pointer as *mut u64, value);
    }
}

/// Writes the low 32 bits of `value` to `pointer` (32-bit targets).
#[cfg(target_pointer_width = "32")]
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn fixture_store(pointer: u32, value: u32) {
    // SAFETY: the parent passes the address of `BUFFER`, an 8-byte-aligned
    // static in this process, as printed in the READY line. The write is
    // naturally aligned and stays inside the buffer.
    unsafe {
        std::ptr::write_unaligned(pointer as *mut u32, value);
    }
}

/// Returns a fixed value; proves a zero-argument call works.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn fixture_ping() -> u64 {
    PING_VALUE
}

/// One iteration of the fixture's frame loop.
///
/// Its entry is used as the safe point for the Wine 32-bit tests: the spin
/// loop calls it repeatedly, so a hardware breakpoint there fires promptly
/// while the target is in 32-bit code.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn fixture_tick() -> u64 {
    TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Terminates the fixture process from inside a remote call.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn fixture_exit() -> u64 {
    std::process::exit(0)
}

/// `stdcall` variant for Windows `x86`.
#[cfg(all(windows, target_arch = "x86"))]
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "stdcall" fn fixture_stdcall_add(a: u32, b: u32) -> u64 {
    u64::from(a.wrapping_add(b))
}

/// `fastcall` variant for Windows `x86`.
#[cfg(all(windows, target_arch = "x86"))]
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "fastcall" fn fixture_fastcall_add(a: u32, b: u32) -> u64 {
    u64::from(a.wrapping_add(b))
}

/// `thiscall` variant for Windows `x86`; `this` is ignored.
#[cfg(all(windows, target_arch = "x86"))]
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "thiscall" fn fixture_thiscall_add(this: u32, a: u32, b: u32) -> u64 {
    u64::from(this.wrapping_add(a).wrapping_add(b))
}

/// Converts a function or static address to a numeric target address.
fn address_of(pointer: *const ()) -> u64 {
    pointer as u64
}

fn main() {
    #[allow(unused_mut)] // mutated only on Windows x86
    let mut ready = format!(
        "READY pid={} add={:#x} mix={:#x} store={:#x} ping={:#x} exit={:#x} buffer={:#x} data={:#x}",
        std::process::id(),
        address_of(fixture_add as *const ()),
        address_of(fixture_mix as *const ()),
        address_of(fixture_store as *const ()),
        address_of(fixture_ping as *const ()),
        address_of(fixture_exit as *const ()),
        address_of(std::ptr::addr_of!(BUFFER).cast()),
        address_of(std::ptr::addr_of!(FIXTURE_DATA).cast()),
    );
    {
        use std::fmt::Write as _;
        let _ = write!(ready, " tick={:#x}", address_of(fixture_tick as *const ()),);
    }
    #[cfg(all(windows, target_arch = "x86"))]
    {
        use std::fmt::Write as _;
        let _ = write!(
            ready,
            " stdcall={:#x} fastcall={:#x} thiscall={:#x}",
            address_of(fixture_stdcall_add as *const ()),
            address_of(fixture_fastcall_add as *const ()),
            address_of(fixture_thiscall_add as *const ()),
        );
    }

    println!("{ready}");
    io::stdout().flush().expect("flush READY");

    if std::env::var_os("MEMDIVER_CALL_FIXTURE_SPIN").is_some() {
        loop {
            std::hint::black_box(fixture_tick());
        }
    }

    let stdin = io::stdin();
    let mut line = String::new();
    let mut consecutive_empty_reads = 0u32;
    loop {
        line.clear();
        match stdin.read_line(&mut line) {
            // A remote call can interrupt the blocked `read(2)`. The kernel
            // returns an error or zero bytes, so ignore both and try again.
            Ok(0) => {
                consecutive_empty_reads = consecutive_empty_reads.saturating_add(1);
                if consecutive_empty_reads >= 3 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(_) => {
                consecutive_empty_reads = 0;
                let command = line.trim();
                if command == "PING" {
                    println!("PONG");
                    let _ = io::stdout().flush();
                } else if command == "STOP" {
                    break;
                }
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
}
