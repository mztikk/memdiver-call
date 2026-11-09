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

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::io;
use std::mem::MaybeUninit;
use std::sync::OnceLock;

use memdiver::{Address, Process, RegionMap};

use crate::error::{CallOutcome, CallStatus, OsFailure, SysError};
use crate::frame::{self, STACK_HEADROOM};
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

/// `status >> 16` value for a `PTRACE_EVENT_STOP` stop.
///
/// `libc` exposes this for some targets but not for `linux-gnu`.
const PTRACE_EVENT_STOP: libc::c_int = 128;

/// Direction flag: the ABI requires `DF = 0` at function entry.
const EFLAGS_DF: u64 = 1 << 10;

/// Trap flag: a called function must not single-step the target.
const EFLAGS_TF: u64 = 1 << 8;

/// Resume flag: suppresses the instruction breakpoint for one instruction.
///
/// When the interrupted instruction lies inside the called function, the
/// return breakpoint also fires while the callee executes that instruction.
/// Setting `RF` lets that instruction run once so the breakpoint can fire
/// again at the real return.
const EFLAGS_RF: u64 = 1 << 16;

/// Upper bound on early return-breakpoint hits before the call is failed.
const MAX_EARLY_BREAKPOINT_STOPS: usize = 4096;

/// Upper bound on forwarded signal stops before a call is declared failed.
///
/// This only exists so a pathological signal storm cannot hang the caller
/// forever.
const MAX_SIGNAL_STOPS: usize = 1024;

/// Upper bound for the user xstate area this backend is willing to allocate.
///
/// The architectural xstate area is currently below 11 KiB (AMX); 64 KiB leaves
/// room for future components while still refusing an unexpected size instead
/// of silently truncating it.
const XSTATE_MAX_SIZE: usize = 64 * 1024;

/// Alignment required by the `XSAVE` area.
const XSTATE_ALIGN: usize = 64;

/// Size of the legacy x87/SSE register set (`NT_PRFPREG`).
const FPREGSET_SIZE: usize = std::mem::size_of::<libc::user_fpregs_struct>();

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

/// How the floating-point/SIMD state is saved on this host.
#[derive(Clone, Copy, Debug)]
enum FpLayout {
    /// The extended `XSAVE` area, with this many bytes.
    Xstate(usize),
    /// The legacy x87/SSE register set.
    Legacy,
}

/// Cached host floating-point layout, probed on the first call.
static FP_LAYOUT: OnceLock<FpLayout> = OnceLock::new();

/// Saved floating-point/SIMD register set.
pub(crate) struct FpState {
    buffer: AlignedBuf,
    len: usize,
    regset: u32,
}

/// A 64-byte-aligned, zeroed buffer for the `XSAVE` area.
struct AlignedBuf {
    pointer: std::ptr::NonNull<u8>,
    layout: Layout,
}

impl AlignedBuf {
    /// Allocates a zeroed, 64-byte-aligned buffer of `len` bytes.
    fn new(len: usize) -> Result<Self, SysError> {
        debug_assert!(len > 0, "the xstate buffer is never empty");
        let layout = Layout::from_size_align(len, XSTATE_ALIGN)
            .map_err(|_| allocation_error("the xstate buffer size is invalid"))?;
        // SAFETY: `layout` has a non-zero size because every caller passes a
        // positive length.
        let pointer = unsafe { alloc_zeroed(layout) };
        let Some(pointer) = std::ptr::NonNull::new(pointer) else {
            return Err(allocation_error("the xstate buffer allocation failed"));
        };
        Ok(Self { pointer, layout })
    }

    fn as_ptr(&self) -> *const u8 {
        self.pointer.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.pointer.as_ptr()
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        // SAFETY: `pointer` was allocated with `alloc_zeroed` and `layout`, and
        // this is its only deallocation.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

/// Builds an allocation failure for the floating-point buffer.
fn allocation_error(reason: &'static str) -> SysError {
    SysError::Inspect {
        operation: "allocate the floating-point state buffer",
        source: Box::new(io::Error::other(reason)),
    }
}

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
    let deliver = deliver_on_detach(&result);
    let cleanup = restore_and_detach(
        tid,
        &saved_registers,
        Some(&saved_fp),
        &saved_debug,
        deliver,
    )
    .err();
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
    // One region snapshot serves every address check in this call.
    let regions = process
        .region_map()
        .map_err(inspect("Process::region_map"))?;
    ensure_executable(
        &regions,
        function,
        "the function address is not in an executable region",
    )?;
    ensure_executable(
        &regions,
        saved.rip,
        "the interrupted instruction pointer is not in an executable region",
    )?;
    let layout = frame::layout(saved.rsp, args.len()).ok_or(SysError::InvalidAddress {
        address: saved.rsp,
        reason: "the stack pointer is too low for a call frame",
    })?;
    ensure_frame(&regions, layout.frame, layout.end, saved.rsp)?;

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
    // A real return has popped the synthetic return address, so RSP is above
    // the frame; that is how it is told apart from the callee executing the
    // interrupted instruction itself.
    wait_for_breakpoint(tid, saved.rip, slot, layout.frame)?;
    Ok(get_registers(tid)?.rax)
}

/// Waits for the initial `PTRACE_INTERRUPT` stop.
pub(crate) fn wait_for_initial_stop(tid: libc::pid_t) -> Result<(), SysError> {
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
        if libc::WIFSTOPPED(status) {
            if is_event_stop(status) {
                // `PTRACE_INTERRUPT` reports an event stop with `SIGTRAP`. Any
                // other event stop is a job-control group-stop, which must not
                // be treated as the attach stop.
                if libc::WSTOPSIG(status) == libc::SIGTRAP {
                    return Ok(());
                }
                return Err(SysError::Unsupported {
                    operation: "attach",
                    reason: "the target is stopped by job control",
                });
            }
            // A signal-delivery stop can win the race with PTRACE_INTERRUPT.
            // Forward it instead of dropping it, then keep waiting for the
            // interrupt event stop.
            let signal = libc::WSTOPSIG(status);
            forwarded = forwarded.saturating_add(1);
            if forwarded > MAX_SIGNAL_STOPS {
                return Err(SysError::CallFailed(CallStatus::Signal(signal)));
            }
            resume(tid, signal)?;
            continue;
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            return Err(SysError::TargetExited);
        }
    }
}

/// Waits for the hardware breakpoint at the interrupted instruction.
///
/// `frame` is the address of the synthetic return address. A real return has
/// already popped it, so the callee's stack pointer is above `frame`; a hit at
/// or below `frame` means the callee executed the interrupted instruction
/// itself. That instruction is stepped over with the resume flag and the wait
/// continues. The check is deliberately a comparison rather than an exact
/// value so it also covers callee-cleanup x86 conventions (`ret N`).
pub(crate) fn wait_for_breakpoint(
    tid: libc::pid_t,
    breakpoint: u64,
    slot: u8,
    frame: u64,
) -> Result<(), SysError> {
    let mut forwarded = 0usize;
    let mut early = 0usize;
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
            let registers = get_registers(tid)?;
            if registers.rsp > frame {
                return Ok(());
            }
            early = early.saturating_add(1);
            if early > MAX_EARLY_BREAKPOINT_STOPS {
                return Err(SysError::CallFailed(CallStatus::Signal(signal)));
            }
            let mut stepped = registers;
            stepped.eflags |= EFLAGS_RF;
            set_registers(tid, &stepped)?;
            resume(tid, 0)?;
            continue;
        }
        if is_event_stop(status) {
            // A group-stop (or an interrupt from another tracer) is not a
            // signal-delivery stop; forwarding it would either re-stop the
            // tracee or inject a real SIGTRAP. Abort so the restore path runs.
            return Err(SysError::CallFailed(CallStatus::Signal(signal)));
        }
        // Forward signal-delivery stops to the target. A signal that repeats
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
    fp: Option<&FpState>,
    debug_state: &DebugState,
    deliver: libc::c_int,
) -> Result<(), SysError> {
    let mut failures = Failures::default();
    failures.record(ignore_exited(restore_debug_state(tid, debug_state)));
    if let Some(fp) = fp {
        failures.record(ignore_exited(set_fp_state(tid, fp)));
    }
    failures.record(ignore_exited(set_registers(tid, registers)));
    failures.record(detach_with_signal(tid, deliver));
    failures.into_result()
}

/// Restores the debug registers, clearing `DR6` before touching `DR7`.
///
/// Clearing the breakpoint-status bits first keeps them from being carried
/// into the re-armed state; the saved `DR6` is restored last.
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
    detach_with_signal(tid, 0)
}

/// Detaches the tracee, delivering `signal` if it is non-zero.
///
/// `PTRACE_DETACH` returns `ESRCH` both when the tracee is gone and when it is
/// not stopped. The two cases are distinguished here so a target that is still
/// running is reported instead of being treated as detached.
pub(crate) fn detach_with_signal(tid: libc::pid_t, signal: libc::c_int) -> Result<(), SysError> {
    let data = usize::try_from(signal).unwrap_or(0);
    let detach = || ptrace_raw(libc::PTRACE_DETACH, tid, 0, data, "PTRACE_DETACH");
    match detach() {
        Ok(_) => Ok(()),
        Err(error) if is_esrch(&error) => {
            let mut status: libc::c_int = 0;
            // SAFETY: `status` is writable and `tid` is the traced thread.
            let reaped = unsafe { libc::waitpid(tid, &mut status, libc::__WALL | libc::WNOHANG) };
            if reaped == tid {
                if !libc::WIFSTOPPED(status) {
                    return Ok(());
                }
                // A stop was pending after all; retry the detach once.
                match detach() {
                    Ok(_) => Ok(()),
                    Err(retry) if is_esrch(&retry) => Err(retry),
                    Err(retry) => Err(retry),
                }
            } else if reaped < 0 {
                // ECHILD: the tracee is no longer our child.
                Ok(())
            } else {
                // The task exists but is running, so it was not detached.
                Err(error)
            }
        }
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

/// Returns the cached floating-point layout, probing it on first use.
fn fp_layout(tid: libc::pid_t) -> Result<FpLayout, SysError> {
    if let Some(layout) = FP_LAYOUT.get() {
        return Ok(*layout);
    }
    let layout = probe_fp_layout(tid)?;
    // A concurrent probe installs the same host-wide value.
    let _ = FP_LAYOUT.set(layout);
    Ok(layout)
}

/// Probes the kernel for the real user-xstate size.
///
/// A too-small request is silently truncated by the kernel (the returned
/// `iov_len` is clamped), while `PTRACE_SETREGSET` later requires exactly the
/// architectural size, so the size must be learned rather than guessed.
fn probe_fp_layout(tid: libc::pid_t) -> Result<FpLayout, SysError> {
    let mut buffer = AlignedBuf::new(XSTATE_MAX_SIZE)?;
    let mut iovec = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: XSTATE_MAX_SIZE,
    };
    match regset_request(
        libc::PTRACE_GETREGSET,
        tid,
        NT_X86_XSTATE,
        &mut iovec,
        "PTRACE_GETREGSET",
    ) {
        Ok(()) => {
            if iovec.iov_len == 0 || iovec.iov_len >= XSTATE_MAX_SIZE {
                return Err(SysError::Unsupported {
                    operation: "PTRACE_GETREGSET",
                    reason: "the user xstate area is empty or exceeds the 64 KiB probe buffer",
                });
            }
            Ok(FpLayout::Xstate(iovec.iov_len))
        }
        Err(SysError::Platform(failure)) if unsupported_regset(failure.code()) => {
            Ok(FpLayout::Legacy)
        }
        Err(error) => Err(error),
    }
}

/// Returns `true` when the kernel does not provide the extended xstate set.
fn unsupported_regset(code: i64) -> bool {
    code == i64::from(libc::EINVAL)
        || code == i64::from(libc::EOPNOTSUPP)
        || code == i64::from(libc::ENODEV)
}

/// Reads the floating-point/SIMD state using the probed layout.
pub(crate) fn get_fp_state(tid: libc::pid_t) -> Result<FpState, SysError> {
    let (regset, len) = match fp_layout(tid)? {
        FpLayout::Xstate(size) => (NT_X86_XSTATE, size),
        FpLayout::Legacy => (NT_PRFPREG, FPREGSET_SIZE),
    };
    let mut buffer = AlignedBuf::new(len)?;
    let mut iovec = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: len,
    };
    regset_request(
        libc::PTRACE_GETREGSET,
        tid,
        regset,
        &mut iovec,
        "PTRACE_GETREGSET",
    )?;
    if iovec.iov_len != len {
        return Err(SysError::Unsupported {
            operation: "PTRACE_GETREGSET",
            reason: "the kernel returned a different floating-point state size than the probe",
        });
    }
    Ok(FpState {
        buffer,
        len,
        regset,
    })
}

/// Writes the saved floating-point/SIMD state.
pub(crate) fn set_fp_state(tid: libc::pid_t, state: &FpState) -> Result<(), SysError> {
    let mut iovec = libc::iovec {
        iov_base: state.buffer.as_ptr().cast_mut().cast(),
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
    regions: &RegionMap,
    address: u64,
    reason: &'static str,
) -> Result<(), SysError> {
    match regions.find(Address::new(address)) {
        Some(region) if region.is_executable() => Ok(()),
        Some(_) => Err(SysError::InvalidAddress { address, reason }),
        None => Err(SysError::InvalidAddress {
            address,
            reason: "the address is not in a mapped region",
        }),
    }
}

/// Verifies that the whole frame is in the interrupted stack region and writable.
///
/// The frame must be in the same region as `saved_sp`: a frame that crosses into
/// an adjacent writable mapping would otherwise pass the writability checks and
/// corrupt that mapping.
pub(crate) fn ensure_frame(
    regions: &RegionMap,
    frame: u64,
    end: u64,
    saved_sp: u64,
) -> Result<(), SysError> {
    let Some(region) = regions.find(Address::new(frame)) else {
        return Err(SysError::InvalidAddress {
            address: frame,
            reason: "the call frame is not in a mapped region",
        });
    };
    if !region.contains(Address::new(saved_sp)) {
        return Err(SysError::InvalidAddress {
            address: frame,
            reason: "the call frame is not in the stack region",
        });
    }
    if !region.is_writable() {
        return Err(SysError::InvalidAddress {
            address: frame,
            reason: "the call frame is not writable",
        });
    }
    if frame.saturating_sub(region.base().get()) < STACK_HEADROOM {
        return Err(SysError::InvalidAddress {
            address: frame,
            reason: "there is not enough stack headroom below the call frame",
        });
    }
    if end > region.end().get() {
        return Err(SysError::InvalidAddress {
            address: frame,
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

/// Returns the stop signal to deliver when detaching after a failed call.
///
/// Only a genuine signal-delivery stop carries a signal worth forwarding:
/// `SIGTRAP` is either our own breakpoint or a trap event, and job-control
/// signals must not be re-delivered.
fn deliver_on_detach(result: &Result<u64, SysError>) -> libc::c_int {
    match result {
        Err(SysError::CallFailed(CallStatus::Signal(signal)))
            if *signal != libc::SIGTRAP && !is_group_stop_signal(*signal) =>
        {
            *signal
        }
        _ => 0,
    }
}

/// Returns `true` when `status` reports a `PTRACE_EVENT_STOP`.
pub(crate) fn is_event_stop(status: libc::c_int) -> bool {
    (status >> 16) == PTRACE_EVENT_STOP
}

/// Returns `true` for the job-control signals that arrive as group-stops.
fn is_group_stop_signal(signal: libc::c_int) -> bool {
    signal == libc::SIGSTOP
        || signal == libc::SIGTSTP
        || signal == libc::SIGTTIN
        || signal == libc::SIGTTOU
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
    fn aligned_xstate_buffer_is_aligned_and_zeroed() {
        let mut buffer = AlignedBuf::new(2696).expect("buffer");
        assert_eq!(buffer.as_ptr() as usize % XSTATE_ALIGN, 0);
        // SAFETY: the buffer is valid for 2696 bytes and was zero-initialized.
        unsafe {
            assert_eq!(*buffer.as_mut_ptr(), 0);
        }
    }

    #[test]
    fn unsupported_regset_codes_are_recognized() {
        assert!(unsupported_regset(i64::from(libc::EINVAL)));
        assert!(unsupported_regset(i64::from(libc::EOPNOTSUPP)));
        assert!(unsupported_regset(i64::from(libc::ENODEV)));
        assert!(!unsupported_regset(i64::from(libc::EPERM)));
    }

    #[test]
    fn debug_register_offsets_are_ordered() {
        assert_eq!(debug_register_offset(0), DEBUG_REGISTER_BASE);
        assert_eq!(debug_register_offset(3), DEBUG_REGISTER_BASE + 24);
        assert_eq!(DR6_OFFSET, DEBUG_REGISTER_BASE + 48);
        assert_eq!(DR7_OFFSET, DEBUG_REGISTER_BASE + 56);
    }
}
