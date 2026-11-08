//! Native Linux `x86_64` caller into a 32-bit Windows PE hosted by Wine.
//!
//! Wine runs the 32-bit PE code natively on a Linux thread in 32-bit
//! compatibility mode. The PE image is mapped at its Windows virtual
//! addresses, so a normal Linux `ptrace` attachment sees the 32-bit register
//! state (`CS = 0x23`) and can redirect `EIP`/`ESP` exactly as it would for a
//! native process.
//!
//! The target must be **the process that hosts the PE**, not the `wine`
//! launcher. A `wine` launcher forks the PE host and the host is often
//! reparented to `init`; a caller that spawns Wine should set
//! `PR_SET_CHILD_SUBREAPER` so the PE host stays traceable under Yama.
//!
//! # Safe points
//!
//! A thread stopped inside a Wine syscall is in 64-bit mode (`CS = 0x33`);
//! redirecting it to 32-bit PE code is invalid. A safe point is an instruction
//! address in 32-bit PE code that the game's main thread reaches regularly,
//! for example the instruction after `SwapBuffers` returns or a per-frame tick
//! entry. The backend arms a hardware execution breakpoint at that address,
//! resumes the thread until it arrives, and then performs the call. The same
//! breakpoint catches the return. Without a safe point the backend only calls
//! when the initial stop already happens to be in 32-bit mode.

use std::io;
use std::time::{Duration, Instant};

use memdiver::{Address, Process};

use crate::debug;
use crate::error::{CallOutcome, CallStatus, SysError};
use crate::frame_x86::{self, FrameLayout, STACK_HEADROOM};
use crate::linux::{self, DebugState, FpState};
use crate::{Failures, MAX_ARGUMENTS};

/// `CS` value while executing 32-bit compatibility-mode code.
const CS_I386: u64 = 0x23;

/// Direction flag: the ABI requires `DF = 0` at function entry.
const EFLAGS_DF: u64 = 1 << 10;

/// Trap flag: a called function must not single-step the target.
const EFLAGS_TF: u64 = 1 << 8;

/// How often the safe-point wait re-checks for a stop.
const POLL_INTERVAL: Duration = Duration::from_micros(200);

/// The calling convention of a 32-bit Windows function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WineAbi {
    /// All arguments on the stack; the caller cleans up.
    Cdecl,
    /// All arguments on the stack; the callee cleans up.
    Stdcall,
    /// `this` in `ECX`; the remaining arguments on the stack.
    Thiscall,
    /// First two arguments in `ECX`/`EDX`; the remainder on the stack.
    Fastcall,
}

/// A detected 32-bit Windows PE loaded into a Wine process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WineTarget {
    module_base: u64,
}

impl WineTarget {
    /// Returns the load address of the PE main module.
    #[must_use]
    pub const fn module_base(self) -> u64 {
        self.module_base
    }
}

/// Waits for and attaches to a Wine process.
///
/// The returned value is a guard: dropping it without calling
/// [`Attached::call`] or [`Attached::detach`] detaches without reporting
/// errors.
#[derive(Debug)]
pub struct Attached {
    tid: libc::pid_t,
    armed: bool,
}

impl Attached {
    /// Runs one call with the chosen 32-bit Windows ABI.
    ///
    /// `safe_point` is an instruction address in 32-bit PE code. When it is
    /// `Some`, the thread is resumed until the hardware breakpoint at that
    /// address fires, then the call is made and the same breakpoint catches
    /// the return. When it is `None`, the call is only made if the initial
    /// stop is already in 32-bit mode.
    ///
    /// `timeout` bounds the safe-point wait, not the call itself.
    pub fn call(
        mut self,
        process: &Process,
        function: u64,
        args: &[u64],
        abi: WineAbi,
        safe_point: Option<u64>,
        timeout: Duration,
    ) -> CallOutcome {
        self.armed = false;
        run(self.tid, process, function, args, abi, safe_point, timeout)
    }

    /// Detaches without running a call.
    ///
    /// # Errors
    ///
    /// Returns the operating-system failure when `PTRACE_DETACH` fails. A
    /// target that already exited is treated as detached.
    pub fn detach(mut self) -> Result<(), SysError> {
        self.armed = false;
        linux::detach(self.tid)
    }
}

impl Drop for Attached {
    fn drop(&mut self) {
        if self.armed {
            let _ = linux::detach(self.tid);
        }
    }
}

/// Attaches to the Wine PE process `pid` and stops its main thread.
///
/// # Errors
///
/// Returns [`SysError::Unsupported`] when `tid` is not the main thread or the
/// target has CET shadow stack enabled, [`SysError::TargetExited`] when the
/// target is gone, and [`SysError::Platform`] when `ptrace` fails (for example
/// because Yama denies access or another tracer exists).
pub fn attach(pid: u32, tid: u32) -> Result<Attached, SysError> {
    if tid != pid {
        return Err(SysError::Unsupported {
            operation: "attach",
            reason: "only the main thread (TID == PID) is supported",
        });
    }
    let tid = libc::pid_t::try_from(tid).map_err(|_| SysError::InvalidArgument {
        index: usize::MAX,
        reason: "thread id does not fit in a pid_t",
    })?;
    linux::check_shadow_stack(pid)?;
    linux::ptrace_raw(libc::PTRACE_SEIZE, tid, 0, 0, "PTRACE_SEIZE")?;
    if let Err(error) = linux::ptrace_raw(libc::PTRACE_INTERRUPT, tid, 0, 0, "PTRACE_INTERRUPT") {
        let _ = linux::detach(tid);
        return Err(error);
    }
    match linux::wait_for_initial_stop(tid) {
        Ok(()) => Ok(Attached { tid, armed: true }),
        Err(error) => {
            let _ = linux::detach(tid);
            Err(error)
        }
    }
}

/// Detects the 32-bit Windows PE main module of a Wine process.
///
/// Scans the target's file-backed regions for a `.exe` file and parses the PE
/// header at the mapping base.
///
/// # Errors
///
/// Returns [`SysError::Unsupported`] when no 32-bit PE main module is found
/// (including a 64-bit PE), and [`SysError::Inspect`] when region enumeration
/// fails.
pub fn detect(process: &Process) -> Result<WineTarget, SysError> {
    let regions = process
        .regions()
        .map_err(linux::inspect("Process::regions"))?;
    let mut saw_64_bit = false;
    for region in regions.iter() {
        let Some(path) = region.path() else {
            continue;
        };
        let is_exe = path
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"));
        if !is_exe || !region.is_readable() || region.size() < 0x40 {
            continue;
        }
        let base = region.base().get();
        let mut dos = [0u8; 0x40];
        if process.read(Address::new(base), &mut dos).is_err() {
            continue;
        }
        if &dos[0..2] != b"MZ" {
            continue;
        }
        let e_lfanew = u64::from(u32::from_le_bytes([
            dos[0x3c], dos[0x3d], dos[0x3e], dos[0x3f],
        ]));
        if e_lfanew < 4 || e_lfanew + 32 > region.size() {
            continue;
        }
        let Some(header_address) = base.checked_add(e_lfanew) else {
            continue;
        };
        let mut header = [0u8; 32];
        if process
            .read(Address::new(header_address), &mut header)
            .is_err()
        {
            continue;
        }
        if &header[0..4] != b"PE\0\0" {
            continue;
        }
        let machine = u16::from_le_bytes([header[4], header[5]]);
        let magic = u16::from_le_bytes([header[24], header[25]]);
        if magic == 0x20b {
            saw_64_bit = true;
            continue;
        }
        if machine != 0x014c || magic != 0x10b {
            continue;
        }
        return Ok(WineTarget { module_base: base });
    }
    let reason = if saw_64_bit {
        "the target's main module is a 64-bit PE; only 32-bit Wine targets are supported"
    } else {
        "no 32-bit Windows PE main module was found; is the target a Wine PE process?"
    };
    Err(SysError::Unsupported {
        operation: "RemoteCaller::open_wine",
        reason,
    })
}

/// Saved argument placement for a 32-bit Windows call.
#[derive(Debug)]
struct ArgumentLayout {
    ecx: Option<u32>,
    edx: Option<u32>,
    stack: Vec<u32>,
}

/// Splits arguments into register and stack slots for `abi`.
fn layout_arguments(abi: WineAbi, args: &[u32]) -> ArgumentLayout {
    match abi {
        WineAbi::Cdecl | WineAbi::Stdcall => ArgumentLayout {
            ecx: None,
            edx: None,
            stack: args.to_vec(),
        },
        WineAbi::Thiscall => ArgumentLayout {
            ecx: args.first().copied(),
            edx: None,
            stack: args.get(1..).unwrap_or(&[]).to_vec(),
        },
        WineAbi::Fastcall => ArgumentLayout {
            ecx: args.first().copied(),
            edx: args.get(1).copied(),
            stack: args.get(2..).unwrap_or(&[]).to_vec(),
        },
    }
}

/// Runs a call on a stopped Wine thread and always attempts restore/detach.
fn run(
    tid: libc::pid_t,
    process: &Process,
    function: u64,
    args: &[u64],
    abi: WineAbi,
    safe_point: Option<u64>,
    timeout: Duration,
) -> CallOutcome {
    if args.len() > MAX_ARGUMENTS {
        return CallOutcome {
            result: Err(SysError::InvalidArgument {
                index: MAX_ARGUMENTS,
                reason: "at most six arguments are supported",
            }),
            cleanup: linux::detach(tid).err(),
        };
    }
    for (index, argument) in args.iter().enumerate() {
        if *argument > u64::from(u32::MAX) {
            return CallOutcome {
                result: Err(SysError::InvalidArgument {
                    index,
                    reason: "the value does not fit in a 32-bit argument slot",
                }),
                cleanup: linux::detach(tid).err(),
            };
        }
    }
    if function > u64::from(u32::MAX) {
        return CallOutcome {
            result: Err(SysError::InvalidAddress {
                address: function,
                reason: "the function address does not fit in a 32-bit target",
            }),
            cleanup: linux::detach(tid).err(),
        };
    }
    if let Some(safe_point) = safe_point {
        if safe_point > u64::from(u32::MAX) {
            return CallOutcome {
                result: Err(SysError::InvalidAddress {
                    address: safe_point,
                    reason: "the safe point does not fit in a 32-bit target",
                }),
                cleanup: linux::detach(tid).err(),
            };
        }
        if safe_point == function {
            return CallOutcome {
                result: Err(SysError::InvalidArgument {
                    index: 0,
                    reason: "the safe point must differ from the function address",
                }),
                cleanup: linux::detach(tid).err(),
            };
        }
    }

    let initial = match linux::get_registers(tid) {
        Ok(registers) => registers,
        Err(error) => {
            return CallOutcome {
                result: Err(error),
                cleanup: linux::detach(tid).err(),
            };
        }
    };
    let debug = match linux::read_debug_state(tid) {
        Ok(state) => state,
        Err(error) => {
            return CallOutcome {
                result: Err(error),
                cleanup: linux::detach(tid).err(),
            };
        }
    };
    if let Err(error) = linux::ensure_executable(
        process,
        function,
        "the function address is not in an executable region",
    ) {
        return CallOutcome {
            result: Err(error),
            cleanup: linux::detach(tid).err(),
        };
    }
    if let Some(safe_point) = safe_point {
        if let Err(error) = linux::ensure_executable(
            process,
            safe_point,
            "the safe point is not in an executable region",
        ) {
            return CallOutcome {
                result: Err(error),
                cleanup: linux::detach(tid).err(),
            };
        }
    }

    // Choose the stop to make the call from. The state saved for the final
    // restore is the state at that stop, not the initial attach state: the
    // thread legitimately executes until it reaches the safe point.
    let (base, fp) = match safe_point {
        Some(safe_point) if initial.cs == CS_I386 && initial.rip == safe_point => {
            match linux::get_fp_state(tid) {
                Ok(fp) => (initial, fp),
                Err(error) => {
                    return CallOutcome {
                        result: Err(error),
                        cleanup: linux::detach(tid).err(),
                    };
                }
            }
        }
        Some(safe_point) => {
            let slot = match debug::free_slot(debug.dr7) {
                Some(slot) => slot,
                None => {
                    return CallOutcome {
                        result: Err(SysError::Unsupported {
                            operation: "remote call",
                            reason: "the target uses all four hardware debug registers",
                        }),
                        cleanup: linux::detach(tid).err(),
                    };
                }
            };
            if let Err(error) = arm(tid, slot, safe_point, debug.dr7) {
                return fail_armed(tid, &debug, error);
            }
            if let Err(error) = linux::resume(tid, 0) {
                return fail_armed(tid, &debug, error);
            }
            match wait_for_safe_point(tid, safe_point, slot, timeout) {
                Ok(SafePoint::Hit(registers)) => match linux::get_fp_state(tid) {
                    Ok(fp) => (*registers, fp),
                    Err(error) => return fail_armed(tid, &debug, error),
                },
                Ok(SafePoint::TimedOut) => {
                    // `wait_for_safe_point` interrupts and stops the tracee
                    // before returning `TimedOut`.
                    let registers = match linux::get_registers(tid) {
                        Ok(registers) => registers,
                        Err(error) => return fail_after_wait(tid, &debug, error),
                    };
                    let fp = match linux::get_fp_state(tid) {
                        Ok(fp) => fp,
                        Err(error) => return fail_armed(tid, &debug, error),
                    };
                    return fail_state(
                        tid,
                        &registers,
                        &fp,
                        &debug,
                        SysError::SafePointTimeout {
                            address: safe_point,
                            timeout,
                        },
                    );
                }
                Err(error) => return fail_after_wait(tid, &debug, error),
            }
        }
        None => {
            if initial.cs != CS_I386 {
                return CallOutcome {
                    result: Err(SysError::Unsupported {
                        operation: "remote call",
                        reason: "the target is stopped in 64-bit Wine code; provide a safe point in 32-bit code",
                    }),
                    cleanup: linux::detach(tid).err(),
                };
            }
            match linux::get_fp_state(tid) {
                Ok(fp) => (initial, fp),
                Err(error) => {
                    return CallOutcome {
                        result: Err(error),
                        cleanup: linux::detach(tid).err(),
                    };
                }
            }
        }
    };

    if base.rip == function {
        return fail_state(
            tid,
            &base,
            &fp,
            &debug,
            SysError::InvalidArgument {
                index: 0,
                reason: "the function address equals the return address",
            },
        );
    }

    let slot = match debug::free_slot(debug.dr7) {
        Some(slot) => slot,
        None => {
            return fail_state(
                tid,
                &base,
                &fp,
                &debug,
                SysError::Unsupported {
                    operation: "remote call",
                    reason: "the target uses all four hardware debug registers",
                },
            );
        }
    };
    // Arm the return breakpoint at the safe point / interrupted instruction.
    if let Err(error) = arm(tid, slot, base.rip, debug.dr7) {
        return fail_state(tid, &base, &fp, &debug, error);
    }

    let narrow: Vec<u32> = args.iter().map(|argument| *argument as u32).collect();
    let arguments = layout_arguments(abi, &narrow);
    let frame = match frame_x86::layout(base.rsp, arguments.stack.len()) {
        Some(frame) => frame,
        None => {
            return fail_state(
                tid,
                &base,
                &fp,
                &debug,
                SysError::InvalidAddress {
                    address: base.rsp,
                    reason: "the stack pointer is too low for a call frame",
                },
            );
        }
    };
    if let Err(error) = ensure_frame(process, frame) {
        return fail_state(tid, &base, &fp, &debug, error);
    }

    // Return address followed by the stack arguments.
    let capacity = usize::try_from(frame.end - frame.frame).unwrap_or(28);
    let mut payload = Vec::with_capacity(capacity);
    payload.extend_from_slice(&(base.rip as u32).to_le_bytes());
    for argument in &arguments.stack {
        payload.extend_from_slice(&argument.to_le_bytes());
    }
    if let Err(source) = process.write(Address::new(frame.frame), &payload) {
        return fail_state(
            tid,
            &base,
            &fp,
            &debug,
            SysError::Inspect {
                operation: "Process::write",
                source: Box::new(source),
            },
        );
    }

    let mut registers = base;
    registers.rip = function;
    registers.rsp = frame.frame;
    registers.rax = 0;
    registers.rcx = 0;
    registers.rdx = 0;
    registers.orig_rax = u64::MAX;
    // The ABI requires the direction flag to be clear at function entry, and
    // the trap flag must not single-step the callee.
    registers.eflags &= !(EFLAGS_DF | EFLAGS_TF);
    if let Some(value) = arguments.ecx {
        registers.rcx = u64::from(value);
    }
    if let Some(value) = arguments.edx {
        registers.rdx = u64::from(value);
    }
    if let Err(error) = linux::set_registers(tid, &registers) {
        return fail_state(tid, &base, &fp, &debug, error);
    }

    if let Err(error) = linux::resume(tid, 0) {
        return fail_state(tid, &base, &fp, &debug, error);
    }
    if let Err(error) = linux::wait_for_breakpoint(tid, base.rip, slot) {
        return fail_state(tid, &base, &fp, &debug, error);
    }
    let hit = match linux::get_registers(tid) {
        Ok(registers) => registers,
        Err(error) => return fail_state(tid, &base, &fp, &debug, error),
    };
    if hit.cs != CS_I386 {
        return fail_state(
            tid,
            &base,
            &fp,
            &debug,
            SysError::Unsupported {
                operation: "remote call",
                reason: "the return breakpoint was hit outside 32-bit mode",
            },
        );
    }

    let result = (u64::from(hit.rdx as u32) << 32) | u64::from(hit.rax as u32);
    let cleanup = linux::restore_and_detach(tid, &base, &fp, &debug).err();
    CallOutcome {
        result: Ok(result),
        cleanup,
    }
}

/// The outcome of waiting for a safe point.
enum SafePoint {
    Hit(Box<libc::user_regs_struct>),
    TimedOut,
}

/// Waits until the hardware breakpoint at `safe_point` fires.
///
/// On timeout the tracee is interrupted and stopped so the caller can restore
/// and detach it.
fn wait_for_safe_point(
    tid: libc::pid_t,
    safe_point: u64,
    slot: u8,
    timeout: Duration,
) -> Result<SafePoint, SysError> {
    let deadline = Instant::now().checked_add(timeout);
    loop {
        match poll(tid, deadline)? {
            Poll::Exited => return Err(SysError::CallFailed(CallStatus::Exited)),
            Poll::TimedOut => {
                // The tracee may have stopped between the poll and this
                // interrupt, so an interrupt error is not fatal; wait for the
                // pending stop instead.
                let _ = linux::ptrace_raw(libc::PTRACE_INTERRUPT, tid, 0, 0, "PTRACE_INTERRUPT");
                linux::wait_for_initial_stop(tid)?;
                return Ok(SafePoint::TimedOut);
            }
            Poll::Stopped(status) => {
                let signal = libc::WSTOPSIG(status);
                if signal == libc::SIGTRAP && linux::is_breakpoint_hit(tid, safe_point, slot) {
                    let registers = linux::get_registers(tid)?;
                    if registers.cs == CS_I386 {
                        return Ok(SafePoint::Hit(Box::new(registers)));
                    }
                    return Err(SysError::Unsupported {
                        operation: "remote call",
                        reason: "the safe point was hit outside 32-bit mode",
                    });
                }
                let deliver = if linux::get_siginfo(tid).is_ok() {
                    signal
                } else {
                    0
                };
                linux::resume(tid, deliver)?;
            }
        }
    }
}

/// One non-blocking wait result.
enum Poll {
    Stopped(libc::c_int),
    Exited,
    TimedOut,
}

/// Polls for a tracee stop without blocking past `deadline`.
fn poll(tid: libc::pid_t, deadline: Option<Instant>) -> Result<Poll, SysError> {
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: `status` is a writable `c_int` and `tid` is the traced
        // thread owned by this process.
        let result = unsafe { libc::waitpid(tid, &mut status, libc::__WALL | libc::WNOHANG) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(linux::platform("waitpid", &error));
        }
        if result == 0 {
            if let Some(deadline) = deadline {
                if Instant::now() >= deadline {
                    return Ok(Poll::TimedOut);
                }
            }
            std::thread::sleep(POLL_INTERVAL);
            continue;
        }
        if libc::WIFSTOPPED(status) {
            return Ok(Poll::Stopped(status));
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            return Ok(Poll::Exited);
        }
    }
}

/// Arms the hardware execution breakpoint in `slot` at `address`.
fn arm(tid: libc::pid_t, slot: u8, address: u64, saved_dr7: u64) -> Result<(), SysError> {
    // Acknowledge DR6 first: POKEUSER(DR7) can fail while a status bit is set.
    linux::poke_user(tid, linux::DR6_OFFSET, 0, "PTRACE_POKEUSER(DR6)")?;
    linux::poke_user(
        tid,
        linux::debug_register_offset(slot),
        address,
        "PTRACE_POKEUSER(DR0-DR3)",
    )?;
    linux::poke_user(
        tid,
        linux::DR7_OFFSET,
        debug::enable_execute(saved_dr7, slot),
        "PTRACE_POKEUSER(DR7)",
    )?;
    Ok(())
}

/// Restores the debug registers after a failed arming step and detaches.
///
/// The general-purpose and floating-point state were not modified yet.
fn fail_armed(tid: libc::pid_t, debug: &DebugState, error: SysError) -> CallOutcome {
    let mut failures = Failures::default();
    failures.record(linux::restore_debug_state(tid, debug));
    failures.record(linux::detach(tid));
    CallOutcome {
        result: Err(error),
        cleanup: failures.into_option(),
    }
}

/// Restores and detaches after a safe-point wait error.
///
/// The tracee may be stopped or still running; both cases are handled so the
/// armed debug registers are not left behind.
fn fail_after_wait(tid: libc::pid_t, debug: &DebugState, error: SysError) -> CallOutcome {
    if let Ok(registers) = linux::get_registers(tid) {
        if let Ok(fp) = linux::get_fp_state(tid) {
            return fail_state(tid, &registers, &fp, debug, error);
        }
    }
    if interrupt_and_stop(tid).is_ok() {
        if let Ok(registers) = linux::get_registers(tid) {
            if let Ok(fp) = linux::get_fp_state(tid) {
                return fail_state(tid, &registers, &fp, debug, error);
            }
        }
    }
    let _ = linux::restore_debug_state(tid, debug);
    CallOutcome {
        result: Err(error),
        cleanup: linux::detach(tid).err(),
    }
}

/// Interrupts a running tracee and waits for the stop.
fn interrupt_and_stop(tid: libc::pid_t) -> Result<(), SysError> {
    let _ = linux::ptrace_raw(libc::PTRACE_INTERRUPT, tid, 0, 0, "PTRACE_INTERRUPT");
    linux::wait_for_initial_stop(tid)
}

/// Restores the selected stop state and detaches, keeping the failure.
fn fail_state(
    tid: libc::pid_t,
    base: &libc::user_regs_struct,
    fp: &FpState,
    debug: &DebugState,
    error: SysError,
) -> CallOutcome {
    let cleanup = linux::restore_and_detach(tid, base, fp, debug).err();
    CallOutcome {
        result: Err(error),
        cleanup,
    }
}

/// Verifies that the whole frame is writable and far enough above the guard.
fn ensure_frame(process: &Process, layout: FrameLayout) -> Result<(), SysError> {
    let region = match process.region_at(Address::new(layout.frame)) {
        Ok(Some(region)) => region,
        Ok(None) => {
            return Err(SysError::InvalidAddress {
                address: layout.frame,
                reason: "the call frame is not in a mapped region",
            });
        }
        Err(source) => {
            return Err(SysError::Inspect {
                operation: "Process::region_at",
                source: Box::new(source),
            });
        }
    };
    if !region.is_writable() {
        return Err(SysError::InvalidAddress {
            address: layout.frame,
            reason: "the call frame is not writable",
        });
    }
    if layout.frame.saturating_sub(region.base().get()) < STACK_HEADROOM {
        return Err(SysError::InvalidAddress {
            address: layout.frame,
            reason: "there is not enough stack headroom below the call frame",
        });
    }
    if layout.end > region.end().get() {
        return Err(SysError::InvalidAddress {
            address: layout.frame,
            reason: "the call frame crosses a region boundary",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdecl_puts_every_argument_on_the_stack() {
        let layout = layout_arguments(WineAbi::Cdecl, &[1, 2, 3]);
        assert_eq!(layout.ecx, None);
        assert_eq!(layout.edx, None);
        assert_eq!(layout.stack, vec![1, 2, 3]);
    }

    #[test]
    fn stdcall_puts_every_argument_on_the_stack() {
        let layout = layout_arguments(WineAbi::Stdcall, &[7]);
        assert_eq!(layout.ecx, None);
        assert_eq!(layout.stack, vec![7]);
    }

    #[test]
    fn thiscall_takes_this_from_ecx() {
        let layout = layout_arguments(WineAbi::Thiscall, &[0xAA, 1, 2]);
        assert_eq!(layout.ecx, Some(0xAA));
        assert_eq!(layout.edx, None);
        assert_eq!(layout.stack, vec![1, 2]);
    }

    #[test]
    fn fastcall_uses_both_register_arguments() {
        let layout = layout_arguments(WineAbi::Fastcall, &[0x11, 0x22, 3, 4]);
        assert_eq!(layout.ecx, Some(0x11));
        assert_eq!(layout.edx, Some(0x22));
        assert_eq!(layout.stack, vec![3, 4]);
    }

    #[test]
    fn six_stack_arguments_fit_the_frame() {
        let layout = layout_arguments(WineAbi::Cdecl, &[1, 2, 3, 4, 5, 6]);
        let frame = frame_x86::layout(0x0036_feb8, layout.stack.len()).expect("frame");
        assert_eq!(frame.frame % 16, 12);
        assert_eq!(frame.end, frame.frame + 4 + 24);
    }

    #[test]
    fn fastcall_with_one_argument_leaves_edx_unset() {
        let layout = layout_arguments(WineAbi::Fastcall, &[9]);
        assert_eq!(layout.ecx, Some(9));
        assert_eq!(layout.edx, None);
        assert!(layout.stack.is_empty());
    }
}
