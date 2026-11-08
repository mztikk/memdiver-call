//! Linux `ptrace` backend.
//!
//! The mechanism redirects the interrupted thread's `RIP` to the target
//! function, uses a hardware execution breakpoint at the interrupted
//! instruction as a return breakpoint, saves and restores the full thread
//! state, and detaches. It never writes to target code.
//!
//! # Safety model
//!
//! Only the selected thread is stopped. The target's other threads keep
//! running. The called function therefore runs in the context of a thread
//! that may hold locks or own thread-local state; the library cannot make that
//! transparent. The caller owns the consequences.

use std::io;
use std::mem::MaybeUninit;

use memdiver::{Address, Process};

use crate::error::{CallOutcome, CallStatus, OsFailure, SysError};
use crate::frame::{self, FrameLayout, STACK_HEADROOM};
use crate::{Failures, MAX_ARGUMENTS, debug};

/// `PTRACE_GETREGSET`/`PTRACE_SETREGSET` identifier for the extended xstate.
const NT_X86_XSTATE: u32 = 0x202;

/// `PTRACE_GETREGSET`/`PTRACE_SETREGSET` identifier for the legacy FP state.
///
/// This is `NT_FPREGSET`/`NT_PRFPREG` (both are 2) on x86.
const NT_PRFPREG: u32 = 2;

/// `siginfo_t::si_code` for a hardware-breakpoint trap.
///
/// This is `TRAP_HWBKPT` from `asm/trap_pf.h`; `libc` does not export it.
const TRAP_HWBKPT: i32 = 4;

/// Direction flag: the ABI requires `DF = 0` at function entry.
const EFLAGS_DF: u64 = 1 << 10;

/// Trap flag: a called function must not single-step the target.
const EFLAGS_TF: u64 = 1 << 8;

/// Upper bound on forwarded signal stops before a call is declared failed.
///
/// This only exists so a pathological signal storm cannot hang the caller
/// forever.
const MAX_SIGNAL_STOPS: usize = 1024;

/// Maximum size of the extended xstate area (`XSAVE`).
const XSTATE_BUFFER_SIZE: usize = 4096;

/// Byte offset of `u_debugreg[0]` in `struct user`.
const DEBUG_REGISTER_BASE: usize = std::mem::offset_of!(libc::user, u_debugreg);

/// `DR6` holds the breakpoint status bits.
pub(crate) const DR6_OFFSET: usize = DEBUG_REGISTER_BASE + 6 * 8;

/// `DR7` holds the breakpoint control bits.
pub(crate) const DR7_OFFSET: usize = DEBUG_REGISTER_BASE + 7 * 8;

/// A thread stopped by [`attach`], with best-effort detach on drop.
///
/// The value is a guard: dropping it without calling [`Attached::call`] or
/// [`Attached::detach`] detaches without reporting errors. The explicit
/// methods report them.
#[derive(Debug)]
pub struct Attached {
    tid: libc::pid_t,
    armed: bool,
}

impl Attached {
    /// Runs the call on the stopped thread, restores the saved state, and
    /// detaches.
    ///
    /// The result and any cleanup failure are returned separately; see
    /// [`CallOutcome`].
    pub fn call(mut self, process: &Process, function: u64, args: &[u64]) -> CallOutcome {
        self.armed = false;
        run(self.tid, process, function, args)
    }

    /// Detaches without running a call.
    ///
    /// # Errors
    ///
    /// Returns the operating-system failure when `PTRACE_DETACH` fails. A
    /// target that already exited (`ESRCH`) is treated as detached.
    pub fn detach(mut self) -> Result<(), SysError> {
        self.armed = false;
        detach(self.tid)
    }
}

impl Drop for Attached {
    fn drop(&mut self) {
        if self.armed {
            let _ = detach(self.tid);
        }
    }
}

/// Attaches to `tid` and stops it.
///
/// `pid` is used for the shadow-stack check and must be the thread-group
/// leader; v1 only supports the main thread, so `tid` must equal `pid`.
///
/// # Errors
///
/// Returns [`SysError::Unsupported`] when CET shadow stack is enabled for the
/// target, [`SysError::TargetExited`] when the target is gone, and
/// [`SysError::Platform`] when `ptrace` fails (for example because another
/// tracer exists or Yama denies access).
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

    check_shadow_stack(pid)?;

    ptrace_raw(libc::PTRACE_SEIZE, tid, 0, 0, "PTRACE_SEIZE")?;
    if let Err(error) = ptrace_raw(libc::PTRACE_INTERRUPT, tid, 0, 0, "PTRACE_INTERRUPT") {
        let _ = detach(tid);
        return Err(error);
    }
    match wait_for_initial_stop(tid) {
        Ok(()) => Ok(Attached { tid, armed: true }),
        Err(error) => {
            let _ = detach(tid);
            Err(error)
        }
    }
}

/// Saved debug-register state.
#[derive(Debug)]
pub(crate) struct DebugState {
    pub(crate) slots: [u64; 4],
    pub(crate) dr6: u64,
    pub(crate) dr7: u64,
}

/// Saved floating-point/SIMD register set.
pub(crate) struct FpState {
    buffer: Box<AlignedBuffer>,
    len: usize,
    regset: u32,
}

/// A 64-byte-aligned buffer for the `XSAVE` area.
#[repr(align(64))]
struct AlignedBuffer([u8; XSTATE_BUFFER_SIZE]);

/// Runs a call on a stopped thread and always attempts restore and detach.
fn run(tid: libc::pid_t, process: &Process, function: u64, args: &[u64]) -> CallOutcome {
    let saved_registers = match get_registers(tid) {
        Ok(registers) => registers,
        Err(error) => {
            return CallOutcome {
                result: Err(error),
                cleanup: detach(tid).err(),
            };
        }
    };
    let saved_fp = match get_fp_state(tid) {
        Ok(state) => state,
        Err(error) => {
            return CallOutcome {
                result: Err(error),
                cleanup: detach(tid).err(),
            };
        }
    };
    let saved_debug = match read_debug_state(tid) {
        Ok(state) => state,
        Err(error) => {
            return CallOutcome {
                result: Err(error),
                cleanup: detach(tid).err(),
            };
        }
    };

    let result = execute(tid, process, function, args, &saved_registers, &saved_debug);
    let cleanup = restore_and_detach(tid, &saved_registers, &saved_fp, &saved_debug).err();
    CallOutcome { result, cleanup }
}

/// Performs the redirection, resume, breakpoint wait, and result read.
fn execute(
    tid: libc::pid_t,
    process: &Process,
    function: u64,
    args: &[u64],
    saved: &libc::user_regs_struct,
    saved_debug: &DebugState,
) -> Result<u64, SysError> {
    ensure_executable(
        process,
        function,
        "the function address is not in an executable region",
    )?;
    ensure_executable(
        process,
        saved.rip,
        "the interrupted instruction pointer is not in an executable region",
    )?;

    let layout = frame::layout(saved.rsp, args.len()).ok_or(SysError::InvalidAddress {
        address: saved.rsp,
        reason: "the stack pointer is too low for a call frame",
    })?;
    ensure_frame(process, layout)?;

    let slot = debug::free_slot(saved_debug.dr7).ok_or(SysError::Unsupported {
        operation: "remote call",
        reason: "the target uses all four hardware debug registers",
    })?;

    // Return address followed by arguments 7 and later, written in one
    // transfer so the frame is never observed half-built by another thread
    // that shares the stack.
    let mut frame_bytes =
        Vec::with_capacity(usize::try_from(layout.end - layout.frame).unwrap_or(8));
    frame_bytes.extend_from_slice(&saved.rip.to_le_bytes());
    for argument in args.get(MAX_ARGUMENTS..).unwrap_or(&[]) {
        frame_bytes.extend_from_slice(&argument.to_le_bytes());
    }
    process
        .write(Address::new(layout.frame), &frame_bytes)
        .map_err(inspect("Process::write"))?;

    // Arm the breakpoint before redirecting execution. Arm after the frame
    // write so a failing write never leaves a breakpoint behind.
    poke_user(
        tid,
        debug_register_offset(slot),
        saved.rip,
        "PTRACE_POKEUSER(DR0-DR3)",
    )?;
    poke_user(
        tid,
        DR7_OFFSET,
        debug::enable_execute(saved_debug.dr7, slot),
        "PTRACE_POKEUSER(DR7)",
    )?;

    let mut registers = *saved;
    registers.rip = function;
    registers.rsp = layout.frame;
    // Cancel a pending syscall restart; otherwise a thread stopped inside a
    // blocking syscall resumes the wrong instruction.
    registers.orig_rax = u64::MAX;
    // The ABI requires the direction flag to be clear at function entry, and
    // the trap flag must not single-step the callee.
    registers.eflags &= !(EFLAGS_DF | EFLAGS_TF);
    for (index, argument) in args.iter().take(MAX_ARGUMENTS).enumerate() {
        match index {
            0 => registers.rdi = *argument,
            1 => registers.rsi = *argument,
            2 => registers.rdx = *argument,
            3 => registers.rcx = *argument,
            4 => registers.r8 = *argument,
            5 => registers.r9 = *argument,
            _ => {}
        }
    }
    set_registers(tid, &registers)?;

    resume(tid, 0)?;
    wait_for_breakpoint(tid, saved.rip, slot)?;
    Ok(get_registers(tid)?.rax)
}

/// Waits for the initial `PTRACE_INTERRUPT` stop.
pub(crate) fn wait_for_initial_stop(tid: libc::pid_t) -> Result<(), SysError> {
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: `status` is a valid, writable `c_int`; `tid` is the traced
        // thread owned by this process.
        let result = unsafe { libc::waitpid(tid, &mut status, libc::__WALL) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(platform("waitpid", &error));
        }
        if libc::WIFSTOPPED(status) {
            return Ok(());
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            return Err(SysError::TargetExited);
        }
    }
}

/// Waits for the hardware breakpoint at the interrupted instruction.
pub(crate) fn wait_for_breakpoint(
    tid: libc::pid_t,
    breakpoint: u64,
    slot: u8,
) -> Result<(), SysError> {
    let mut forwarded = 0usize;
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: `status` is a valid, writable `c_int`; `tid` is the traced
        // thread owned by this process.
        let result = unsafe { libc::waitpid(tid, &mut status, libc::__WALL) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(platform("waitpid", &error));
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            return Err(SysError::CallFailed(CallStatus::Exited));
        }
        if !libc::WIFSTOPPED(status) {
            continue;
        }
        let signal = libc::WSTOPSIG(status);
        if signal == libc::SIGTRAP && is_breakpoint_hit(tid, breakpoint, slot) {
            return Ok(());
        }
        // Forward non-breakpoint signals to the target. A signal that repeats
        // forever must not hang the caller.
        forwarded = forwarded.saturating_add(1);
        if forwarded > MAX_SIGNAL_STOPS {
            return Err(SysError::CallFailed(CallStatus::Signal(signal)));
        }
        resume(tid, signal)?;
    }
}

/// Returns `true` when the current stop is the call-return breakpoint.
pub(crate) fn is_breakpoint_hit(tid: libc::pid_t, breakpoint: u64, slot: u8) -> bool {
    let info = match get_siginfo(tid) {
        Ok(info) => info,
        // A group-stop has no signal information; it cannot be our trap.
        Err(_) => return false,
    };
    if info.si_code != TRAP_HWBKPT {
        return false;
    }
    let registers = match get_registers(tid) {
        Ok(registers) => registers,
        Err(_) => return false,
    };
    if registers.rip != breakpoint {
        return false;
    }
    match peek_user(tid, DR6_OFFSET) {
        Ok(dr6) => debug::is_hit(dr6, slot),
        Err(_) => false,
    }
}

/// Restores every saved register set and detaches.
///
/// All steps are attempted even when an earlier one fails; the first failure
/// is returned. A target that is already gone (`ESRCH`) needs no restore.
pub(crate) fn restore_and_detach(
    tid: libc::pid_t,
    registers: &libc::user_regs_struct,
    fp: &FpState,
    debug_state: &DebugState,
) -> Result<(), SysError> {
    let mut failures = Failures::default();
    failures.record(ignore_exited(restore_debug_state(tid, debug_state)));
    failures.record(ignore_exited(set_fp_state(tid, fp)));
    failures.record(ignore_exited(set_registers(tid, registers)));
    failures.record(detach(tid));
    failures.into_result()
}

/// Restores the debug registers, acknowledging `DR6` before touching `DR7`.
///
/// On the tested kernel `PTRACE_POKEUSER(DR7)` fails with `EIO` while the
/// breakpoint-hit status bit in `DR6` is set, so the status bits are cleared
/// first and the saved `DR6` is restored last.
pub(crate) fn restore_debug_state(tid: libc::pid_t, saved: &DebugState) -> Result<(), SysError> {
    let mut failures = Failures::default();
    failures.record(poke_user(tid, DR6_OFFSET, 0, "PTRACE_POKEUSER(DR6)"));
    failures.record(poke_user(
        tid,
        DR7_OFFSET,
        saved.dr7,
        "PTRACE_POKEUSER(DR7)",
    ));
    for (index, value) in saved.slots.iter().enumerate() {
        failures.record(poke_user(
            tid,
            debug_register_offset(u8::try_from(index).unwrap_or(0)),
            *value,
            "PTRACE_POKEUSER(DR0-DR3)",
        ));
    }
    failures.record(poke_user(
        tid,
        DR6_OFFSET,
        saved.dr6,
        "PTRACE_POKEUSER(DR6)",
    ));
    failures.into_result()
}

/// Detaches the tracee with signal 0.
pub(crate) fn detach(tid: libc::pid_t) -> Result<(), SysError> {
    match ptrace_raw(libc::PTRACE_DETACH, tid, 0, 0, "PTRACE_DETACH") {
        Ok(_) => Ok(()),
        Err(error) if is_esrch(&error) => Ok(()),
        Err(error) => Err(error),
    }
}

/// Resumes the tracee, delivering `signal` if it is non-zero.
pub(crate) fn resume(tid: libc::pid_t, signal: libc::c_int) -> Result<(), SysError> {
    let data = usize::try_from(signal).unwrap_or(0);
    ptrace_raw(libc::PTRACE_CONT, tid, 0, data, "PTRACE_CONT").map(|_| ())
}

/// Reads the general-purpose registers.
pub(crate) fn get_registers(tid: libc::pid_t) -> Result<libc::user_regs_struct, SysError> {
    let mut registers = MaybeUninit::<libc::user_regs_struct>::uninit();
    ptrace_raw(
        libc::PTRACE_GETREGS,
        tid,
        0,
        registers.as_mut_ptr() as usize,
        "PTRACE_GETREGS",
    )?;
    // SAFETY: a successful PTRACE_GETREGS initializes the whole
    // `user_regs_struct` with integer values.
    Ok(unsafe { registers.assume_init() })
}

/// Writes the general-purpose registers.
pub(crate) fn set_registers(
    tid: libc::pid_t,
    registers: &libc::user_regs_struct,
) -> Result<(), SysError> {
    let data = std::ptr::from_ref(registers) as usize;
    ptrace_raw(libc::PTRACE_SETREGS, tid, 0, data, "PTRACE_SETREGS").map(|_| ())
}

/// Reads the signal information for the current stop.
pub(crate) fn get_siginfo(tid: libc::pid_t) -> Result<libc::siginfo_t, SysError> {
    let mut info = MaybeUninit::<libc::siginfo_t>::zeroed();
    ptrace_raw(
        libc::PTRACE_GETSIGINFO,
        tid,
        0,
        info.as_mut_ptr() as usize,
        "PTRACE_GETSIGINFO",
    )?;
    // SAFETY: the buffer was zero-initialized and a successful
    // PTRACE_GETSIGINFO fills the whole `siginfo_t`.
    Ok(unsafe { info.assume_init() })
}

/// Reads the extended floating-point/SIMD state, falling back to FPREGSET.
pub(crate) fn get_fp_state(tid: libc::pid_t) -> Result<FpState, SysError> {
    let mut buffer = Box::new(AlignedBuffer([0u8; XSTATE_BUFFER_SIZE]));
    let mut last_error = None;
    for regset in [NT_X86_XSTATE, NT_PRFPREG] {
        let mut iovec = libc::iovec {
            iov_base: buffer.0.as_mut_ptr().cast(),
            iov_len: XSTATE_BUFFER_SIZE,
        };
        match regset_request(
            libc::PTRACE_GETREGSET,
            tid,
            regset,
            &mut iovec,
            "PTRACE_GETREGSET",
        ) {
            Ok(()) => {
                return Ok(FpState {
                    buffer,
                    len: iovec.iov_len,
                    regset,
                });
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or(SysError::Unsupported {
        operation: "PTRACE_GETREGSET",
        reason: "the kernel did not provide a floating-point register set",
    }))
}

/// Writes the saved floating-point/SIMD state.
pub(crate) fn set_fp_state(tid: libc::pid_t, state: &FpState) -> Result<(), SysError> {
    let mut iovec = libc::iovec {
        iov_base: state.buffer.0.as_ptr().cast_mut().cast(),
        iov_len: state.len,
    };
    regset_request(
        libc::PTRACE_SETREGSET,
        tid,
        state.regset,
        &mut iovec,
        "PTRACE_SETREGSET",
    )
}

/// Performs one `PTRACE_{GET,SET}REGSET` call.
fn regset_request(
    request: libc::c_uint,
    tid: libc::pid_t,
    regset: u32,
    iovec: &mut libc::iovec,
    operation: &'static str,
) -> Result<(), SysError> {
    let data = iovec as *mut libc::iovec as usize;
    let address = usize::try_from(regset).unwrap_or(0);
    ptrace_raw(request, tid, address, data, operation).map(|_| ())
}

/// Reads the four breakpoint slots plus `DR6` and `DR7`.
///
/// `DR4`/`DR5` alias `DR6`/`DR7` on CPUs without debug extensions and are not
/// writable through `ptrace`, so they are not saved.
pub(crate) fn read_debug_state(tid: libc::pid_t) -> Result<DebugState, SysError> {
    let mut slots = [0u64; 4];
    for (index, slot) in slots.iter_mut().enumerate() {
        *slot = peek_user(tid, debug_register_offset(u8::try_from(index).unwrap_or(0)))?;
    }
    Ok(DebugState {
        slots,
        dr6: peek_user(tid, DR6_OFFSET)?,
        dr7: peek_user(tid, DR7_OFFSET)?,
    })
}

/// Reads one word from `struct user`.
pub(crate) fn peek_user(tid: libc::pid_t, offset: usize) -> Result<u64, SysError> {
    let value = ptrace_raw(libc::PTRACE_PEEKUSER, tid, offset, 0, "PTRACE_PEEKUSER")?;
    Ok(value as u64)
}

/// Writes one word to `struct user`.
pub(crate) fn poke_user(
    tid: libc::pid_t,
    offset: usize,
    value: u64,
    operation: &'static str,
) -> Result<(), SysError> {
    let data = usize::try_from(value).unwrap_or(usize::MAX);
    ptrace_raw(libc::PTRACE_POKEUSER, tid, offset, data, operation).map(|_| ())
}

/// Issues one `ptrace` request.
///
/// `address` and `data` are interpreted by the request; their types follow the
/// kernel ABI (`struct user` offset plus a value or pointer encoded as `usize`).
pub(crate) fn ptrace_raw(
    request: libc::c_uint,
    tid: libc::pid_t,
    address: usize,
    data: usize,
    operation: &'static str,
) -> Result<libc::c_long, SysError> {
    // SAFETY: every caller matches the request with the documented argument
    // layout. `address` is either 0, a `struct user` byte offset, or a regset
    // identifier; `data` is either 0, a signal number, or a pointer to a
    // suitably sized and initialized object owned by the caller.
    let result = unsafe {
        libc::ptrace(
            request,
            tid,
            address as *mut libc::c_void,
            data as *mut libc::c_void,
        )
    };
    if result == -1 {
        let error = io::Error::last_os_error();
        if let Some(code) = error.raw_os_error() {
            if code != 0 {
                return Err(SysError::Platform(OsFailure::new(
                    operation,
                    i64::from(code),
                )));
            }
        }
    }
    Ok(result)
}

/// Returns `true` when `DR7` is unavailable because the thread is gone.
pub(crate) fn is_esrch(error: &SysError) -> bool {
    matches!(error, SysError::Platform(failure) if failure.code() == i64::from(libc::ESRCH))
}

/// Treats a target that no longer exists as already restored.
pub(crate) fn ignore_exited(result: Result<(), SysError>) -> Result<(), SysError> {
    match result {
        Err(error) if is_esrch(&error) => Ok(()),
        other => other,
    }
}

/// Rejects a target whose CET shadow stack is enabled.
///
/// The fake-return technique only writes the normal stack, so the callee's
/// `ret` would not match a shadow-stack entry.
pub(crate) fn check_shadow_stack(pid: u32) -> Result<(), SysError> {
    let path = format!("/proc/{pid}/status");
    let status = match std::fs::read_to_string(&path) {
        Ok(status) => status,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(SysError::TargetExited);
        }
        Err(error) => return Err(platform("read /proc/<pid>/status", &error)),
    };
    if shadow_stack_enabled(&status) {
        return Err(SysError::Unsupported {
            operation: "remote call",
            reason: "the target has CET shadow stack (SHSTK) enabled",
        });
    }
    Ok(())
}

/// Parses `x86_Thread_features` and `x86_Thread_features_locked`.
///
/// Bit 0 is `SHSTK`. The kernel prints a hexadecimal mask; an empty value
/// means no thread feature is enabled.
fn shadow_stack_enabled(status: &str) -> bool {
    status
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| {
            let key = key.trim();
            key == "x86_Thread_features" || key == "x86_Thread_features_locked"
        })
        .any(|(_, value)| {
            let value = value.trim();
            if value.is_empty() {
                return false;
            }
            if value
                .split_whitespace()
                .any(|token| token.eq_ignore_ascii_case("shstk"))
            {
                return true;
            }
            let digits = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .unwrap_or(value);
            u64::from_str_radix(digits, 16).is_ok_and(|mask| mask & 1 != 0)
        })
}

/// Verifies that `address` is in an executable region.
pub(crate) fn ensure_executable(
    process: &Process,
    address: u64,
    reason: &'static str,
) -> Result<(), SysError> {
    match process.region_at(Address::new(address)) {
        Ok(Some(region)) if region.is_executable() => Ok(()),
        Ok(Some(_)) => Err(SysError::InvalidAddress { address, reason }),
        Ok(None) => Err(SysError::InvalidAddress {
            address,
            reason: "the address is not in a mapped region",
        }),
        Err(source) => Err(SysError::Inspect {
            operation: "Process::region_at",
            source: Box::new(source),
        }),
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

/// Returns `DR0`–`DR3` offset for `slot`.
pub(crate) fn debug_register_offset(slot: u8) -> usize {
    DEBUG_REGISTER_BASE + usize::from(slot) * 8
}

/// Wraps a `memdiver` failure with the operation name.
pub(crate) fn inspect(operation: &'static str) -> impl FnOnce(memdiver::Error) -> SysError {
    move |source| SysError::Inspect {
        operation,
        source: Box::new(source),
    }
}

/// Builds a platform error from an `io::Error`.
pub(crate) fn platform(operation: &'static str, error: &io::Error) -> SysError {
    SysError::Platform(OsFailure::new(
        operation,
        error.raw_os_error().map_or(-1, i64::from),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shadow_stack_fields_are_parsed() {
        assert!(!shadow_stack_enabled("Name:\tfixture\n"));
        assert!(!shadow_stack_enabled("x86_Thread_features:\n"));
        assert!(!shadow_stack_enabled("x86_Thread_features:\t0\n"));
        assert!(shadow_stack_enabled("x86_Thread_features:\t1\n"));
        assert!(shadow_stack_enabled("x86_Thread_features:\t5\n"));
        assert!(shadow_stack_enabled("x86_Thread_features:\t0x1\n"));
        assert!(shadow_stack_enabled("x86_Thread_features_locked:\t1\n"));
        assert!(shadow_stack_enabled("x86_Thread_features:\tshstk\n"));
    }

    #[test]
    fn debug_register_offsets_are_ordered() {
        assert_eq!(debug_register_offset(0), DEBUG_REGISTER_BASE);
        assert_eq!(debug_register_offset(3), DEBUG_REGISTER_BASE + 24);
        assert_eq!(DR6_OFFSET, DEBUG_REGISTER_BASE + 48);
        assert_eq!(DR7_OFFSET, DEBUG_REGISTER_BASE + 56);
    }
}
