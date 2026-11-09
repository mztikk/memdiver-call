//! The pinned remote caller and its pinning protocol.

use std::fmt;
use std::sync::Mutex;

use memdiver::{Address, PointerWidth, Process, RegionMap};
use memdiver_call_sys::{CallOutcome, SysError};

use crate::error::{Error, PlatformError, status_from_sys};
use crate::options::{CallAbi, CallOptions};

/// Maximum number of argument slots in v1.
const MAX_ARGUMENTS: usize = 6;

/// What kind of target a [`RemoteCaller`] is bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TargetKind {
    /// A process on the same operating system and with the same bitness as the
    /// caller.
    Native,
    /// A 32-bit Windows PE hosted by Wine, called from a native Linux
    /// `x86_64` process.
    ///
    /// This target kind is only produced by [`RemoteCaller::open_wine`] and
    /// [`RemoteCaller::new_wine`].
    Wine32,
}

/// A pinned target process plus the execution resource needed to call into it.
///
/// The caller keeps a writable [`memdiver::Process`] for all memory access and,
/// on Windows, a process handle opened with `PROCESS_CREATE_THREAD` and the
/// other rights the mechanism needs. On Linux no trace is kept between calls:
/// each call attaches to the main thread, runs, restores the thread state, and
/// detaches.
///
/// [`RemoteCaller::open_wine`] targets a 32-bit Windows PE hosted by Wine from
/// a native Linux `x86_64` caller. The target must be the process that hosts
/// the PE (the one whose command line is the PE path), not the `wine`
/// launcher. Wine may reparent that process, so a caller that spawns Wine
/// should set `PR_SET_CHILD_SUBREAPER` to keep it traceable under Yama.
///
/// The type is `Send + Sync`, but calls on one instance are serialized with an
/// internal mutex. Two separate callers for the same target are not
/// coordinated; on Linux the second attach fails with `EPERM` (or `EBUSY` on
/// some kernels) and is reported as [`Error::Open`], not retried.
///
/// # Pinning
///
/// [`RemoteCaller::open`] acquires the execution resource before opening the
/// `memdiver` handle, so the PID cannot have been recycled between the two
/// opens. [`RemoteCaller::new`] adopts an existing handle and verifies
/// liveness on both sides of acquiring the execution resource. Each Linux call
/// repeats the double-liveness check around its per-call attach.
///
/// # Drop
///
/// On Windows the execution handle is closed when the caller is dropped. A call
/// cannot be in flight while `Drop` runs because calls borrow `&self`. On Linux
/// there is nothing persistent to release; the per-call guard restores and
/// detaches even on failure.
pub struct RemoteCaller {
    process: Process,
    #[cfg(windows)]
    execution: memdiver_call_sys::Execution,
    serialization: Mutex<()>,
    kind: TargetKind,
}

impl RemoteCaller {
    /// Opens `pid` and pins it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Open`] when the execution resource or the `memdiver`
    /// handle cannot be opened, [`Error::TargetExited`] when the target exits
    /// during setup, [`Error::Unsupported`] when the target's bitness differs
    /// from the host, [`Error::Memory`] when the pointer width cannot be
    /// queried, and [`Error::Cleanup`] when a resource opened during setup
    /// cannot be released after a failure.
    pub fn open(pid: u32) -> Result<Self, Error> {
        open_pinned(pid)
    }

    /// Adopts an existing `memdiver` handle.
    ///
    /// The handle must be writable. Liveness is checked before and after the
    /// execution resource is acquired, which is the argument that the PID
    /// still refers to the same process instance.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReadOnly`] before any operating-system call when the
    /// handle is read-only, [`Error::TargetExited`] when the target is not
    /// alive, [`Error::Unsupported`] for a bitness mismatch,
    /// [`Error::Memory`] when the pointer width cannot be queried, and
    /// [`Error::Open`]/[`Error::Cleanup`] for resource failures.
    pub fn new(process: Process) -> Result<Self, Error> {
        adopt(process)
    }

    /// Opens the process that hosts a 32-bit Windows PE under Wine.
    ///
    /// `pid` must be the Linux PID of the PE-hosting process, not the `wine`
    /// launcher. The caller must be able to `ptrace` that process: under Yama
    /// `ptrace_scope = 1` it must be a descendant of the caller, which normally
    /// means the caller spawned Wine with `PR_SET_CHILD_SUBREAPER` set.
    /// Processes started by Steam/Proton may live in a different PID namespace
    /// and cannot be reached from outside their container.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Open`] when the memory handle cannot be opened,
    /// [`Error::TargetExited`] when the target is not alive,
    /// [`Error::Unsupported`] when the target is not a 32-bit PE under Wine or
    /// the host is not Linux, and [`Error::Memory`] when detection fails.
    pub fn open_wine(pid: u32) -> Result<Self, Error> {
        open_wine_pinned(pid)
    }

    /// Adopts an existing writable handle for a 32-bit Windows PE under Wine.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReadOnly`] before any operating-system call when the
    /// handle is read-only, [`Error::TargetExited`] when the target is gone,
    /// [`Error::Memory`] when region inspection fails, and
    /// [`Error::Unsupported`] when the target is not a 32-bit PE under Wine or
    /// the host is not Linux.
    pub fn new_wine(process: Process) -> Result<Self, Error> {
        adopt_wine(process)
    }

    /// Returns what kind of target this caller is bound to.
    #[must_use]
    pub fn target_kind(&self) -> TargetKind {
        self.kind
    }

    /// Returns the underlying memory handle.
    #[must_use]
    pub fn process(&self) -> &Process {
        &self.process
    }

    /// Calls `function` with up to six `u64` argument slots.
    ///
    /// The result is the raw 64-bit return value. For a return type narrower
    /// than 64 bits, cast it to the declared type before comparing it: the
    /// upper bits are unspecified on `x86_64` and come from `EDX` on `x86`.
    ///
    /// Pointer arguments are raw target addresses. The caller owns the
    /// pointed-to memory and its lifetime; v1 does not copy strings, structs, or
    /// buffers into the target.
    ///
    /// This method is safe Rust with respect to the caller's memory, but it can
    /// **crash or corrupt the target**. The library cannot validate a function
    /// signature, a calling convention, an argument layout, or the side effects
    /// of the called code. The target may deadlock if the called function needs
    /// a lock held by a thread that is stopped. Use it only on processes you
    /// own or are explicitly authorized to inspect.
    ///
    /// On a 32-bit `x86` target (native Windows `x86` or a Wine 32-bit PE),
    /// [`CallOptions::with_wide_arguments`] marks arguments that occupy two
    /// 32-bit stack slots; unlisted arguments must fit in 32 bits.
    ///
    /// On a Wine 32-bit target, [`CallOptions::with_safe_point`] waits for the
    /// target's main thread to reach a chosen 32-bit instruction before
    /// redirecting it. Without a safe point the call only proceeds when the
    /// thread happens to be stopped in 32-bit code.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] for an unsupported ABI, thread, or host
    /// architecture, [`Error::InvalidArgument`] for more than six arguments or
    /// a value that does not fit the target, [`Error::InvalidAddress`] when the
    /// function is not in an executable live region, [`Error::TargetExited`]
    /// when the target is gone, [`Error::SafePointTimeout`] when a Wine target
    /// never reaches the safe point, [`Error::CallFailed`] when the call did
    /// not return a normal result, [`Error::Open`] when the per-call attach or
    /// execution resource cannot be acquired, [`Error::Platform`] when an
    /// operating-system call fails, [`Error::Memory`] when region inspection
    /// fails, [`Error::Leaked`] when remote memory had to be abandoned, and
    /// [`Error::Cleanup`] when target state could not be restored or resources
    /// could not be released. Validation errors are returned before any
    /// execution resource is attached or created.
    pub fn call(
        &self,
        function: Address,
        args: &[u64],
        options: &CallOptions,
    ) -> Result<u64, Error> {
        let _serialized = self.serialization.lock().map_err(|_| Error::Poisoned)?;
        let pid = self.process.pid();
        if !self.process.is_alive() {
            return Err(Error::TargetExited { pid });
        }
        self.validate(function, args, options)?;
        call_pinned(self, function, args, options)
    }

    /// Resolves a named module export with `memdiver` and calls it.
    ///
    /// The export is rejected before the call when it is not in an executable
    /// live region.
    ///
    /// PE exports are not available for a Wine 32-bit target: `memdiver`
    /// resolves ELF exports on a native Linux host, and the PE is not an ELF
    /// module. Pass the function address to [`RemoteCaller::call`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ExportNotFound`] when the module is loaded but does not
    /// export the name, [`Error::Memory`] when resolution itself fails, and the
    /// same errors as [`RemoteCaller::call`]. In particular, a data export
    /// returns [`Error::InvalidAddress`]. On a Wine 32-bit target this method
    /// always returns [`Error::Unsupported`].
    pub fn call_export(
        &self,
        module: &str,
        export: &str,
        args: &[u64],
        options: &CallOptions,
    ) -> Result<u64, Error> {
        if self.kind == TargetKind::Wine32 {
            return Err(Error::Unsupported {
                operation: "call_export",
                reason: "PE exports cannot be resolved from a native Linux caller; pass the function address",
            });
        }
        let address = self
            .process
            .module_export(module, export)
            .map_err(|source| Error::Memory {
                operation: "Process::module_export",
                source: Box::new(source),
            })?
            .ok_or_else(|| Error::ExportNotFound {
                module: module.to_owned(),
                export: export.to_owned(),
            })?;
        self.call(address, args, options)
    }

    /// Validates a call request before any execution resource is used.
    fn validate(
        &self,
        function: Address,
        args: &[u64],
        options: &CallOptions,
    ) -> Result<(), Error> {
        if args.len() > MAX_ARGUMENTS {
            return Err(Error::InvalidArgument {
                index: MAX_ARGUMENTS,
                reason: "at most six arguments are supported",
            });
        }
        // One region snapshot serves every address check in this call.
        let regions = self.region_map()?;
        match self.kind {
            TargetKind::Wine32 => self.validate_wine32(function, args, options, &regions),
            _ => self.validate_native(function, args, options, &regions),
        }
    }

    /// Validation for a native same-OS, same-bitness target.
    fn validate_native(
        &self,
        function: Address,
        args: &[u64],
        options: &CallOptions,
        regions: &RegionMap,
    ) -> Result<(), Error> {
        let _ = args;
        if options.safe_point().is_some() {
            return Err(Error::Unsupported {
                operation: "call",
                reason: "safe points only apply to Wine 32-bit targets",
            });
        }
        validate_abi(options, self.process.pid())?;
        if function.is_null() {
            return Err(Error::InvalidAddress {
                address: function,
                reason: "the null address is not callable",
            });
        }
        #[cfg(target_arch = "x86")]
        {
            if function.get() > u64::from(u32::MAX) {
                return Err(Error::InvalidAddress {
                    address: function,
                    reason: "the address does not fit in a 32-bit target",
                });
            }
            let wide = wide_flags(args.len(), options)?;
            for (index, argument) in args.iter().enumerate() {
                if !wide[index] && *argument > u64::from(u32::MAX) {
                    return Err(Error::InvalidArgument {
                        index,
                        reason: "the value does not fit in a 32-bit argument slot",
                    });
                }
            }
        }
        #[cfg(not(target_arch = "x86"))]
        {
            if !options.wide_arguments().is_empty() {
                return Err(Error::Unsupported {
                    operation: "call",
                    reason: "64-bit argument specifications only apply to 32-bit x86 targets",
                });
            }
        }
        self.require_executable(regions, function)
    }

    /// Validation for a 32-bit Windows PE under Wine.
    fn validate_wine32(
        &self,
        function: Address,
        args: &[u64],
        options: &CallOptions,
        regions: &RegionMap,
    ) -> Result<(), Error> {
        if function.is_null() {
            return Err(Error::InvalidAddress {
                address: function,
                reason: "the null address is not callable",
            });
        }
        if function.get() > u64::from(u32::MAX) {
            return Err(Error::InvalidAddress {
                address: function,
                reason: "the address does not fit in a 32-bit target",
            });
        }
        let wide = wide_flags(args.len(), options)?;
        for (index, argument) in args.iter().enumerate() {
            if !wide[index] && *argument > u64::from(u32::MAX) {
                return Err(Error::InvalidArgument {
                    index,
                    reason: "the value does not fit in a 32-bit argument slot",
                });
            }
        }
        if let Some(tid) = options.thread() {
            if tid != self.process.pid() {
                return Err(Error::Unsupported {
                    operation: "call",
                    reason: "only the main thread (TID == PID) is supported",
                });
            }
        }
        if let Some(safe_point) = options.safe_point() {
            if safe_point.is_null() {
                return Err(Error::InvalidAddress {
                    address: safe_point,
                    reason: "the null address is not a safe point",
                });
            }
            if safe_point.get() > u64::from(u32::MAX) {
                return Err(Error::InvalidAddress {
                    address: safe_point,
                    reason: "the safe point does not fit in a 32-bit target",
                });
            }
            if safe_point == function {
                return Err(Error::InvalidArgument {
                    index: 0,
                    reason: "the safe point must differ from the function address",
                });
            }
            self.require_executable(regions, safe_point)?;
        }
        self.require_executable(regions, function)
    }

    /// Snapshots the target's regions once for this call.
    fn region_map(&self) -> Result<RegionMap, Error> {
        self.process.region_map().map_err(|source| Error::Memory {
            operation: "Process::region_map",
            source: Box::new(source),
        })
    }

    /// Verifies that `address` is in an executable live region.
    fn require_executable(&self, regions: &RegionMap, address: Address) -> Result<(), Error> {
        match regions.find(address) {
            Some(region) if region.is_executable() => Ok(()),
            Some(_) => Err(Error::InvalidAddress {
                address,
                reason: "the address is not in an executable region",
            }),
            None => Err(Error::InvalidAddress {
                address,
                reason: "the address is not in a live region",
            }),
        }
    }
}

impl fmt::Debug for RemoteCaller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteCaller")
            .field("pid", &self.process.pid())
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// Opens and pins a process on Windows: execution handle first.
#[cfg(windows)]
fn open_pinned(pid: u32) -> Result<RemoteCaller, Error> {
    let execution = memdiver_call_sys::open_execution(pid).map_err(|error| map_open(error, pid))?;
    let process = match Process::open(pid) {
        Ok(process) => process,
        Err(source) => {
            let failure = Error::Open {
                pid,
                operation: "memdiver::Process::open",
                source: Box::new(source),
            };
            return Err(close_after(execution, failure, pid));
        }
    };
    if !process.is_alive() {
        return Err(close_after(execution, Error::TargetExited { pid }, pid));
    }
    if let Err(failure) = check_bitness(&process) {
        return Err(close_after(execution, failure, pid));
    }
    Ok(RemoteCaller {
        process,
        execution,
        serialization: Mutex::new(()),
        kind: TargetKind::Native,
    })
}

/// Opens and pins a process on Linux: trace handshake first.
#[cfg(target_os = "linux")]
fn open_pinned(pid: u32) -> Result<RemoteCaller, Error> {
    let attached = memdiver_call_sys::attach(pid, pid).map_err(|error| map_open(error, pid))?;
    let process = match Process::open(pid) {
        Ok(process) => process,
        Err(source) => {
            let failure = Error::Open {
                pid,
                operation: "memdiver::Process::open",
                source: Box::new(source),
            };
            return Err(detach_after(attached, failure, pid));
        }
    };
    if !process.is_alive() {
        return Err(detach_after(attached, Error::TargetExited { pid }, pid));
    }
    if let Err(failure) = check_bitness(&process) {
        return Err(detach_after(attached, failure, pid));
    }
    attached
        .detach()
        .map_err(|error| cleanup_error(error, pid))?;
    Ok(RemoteCaller {
        process,
        serialization: Mutex::new(()),
        kind: TargetKind::Native,
    })
}

/// Adopts an existing handle on Windows.
#[cfg(windows)]
fn adopt(process: Process) -> Result<RemoteCaller, Error> {
    if !process.is_writable() {
        return Err(Error::ReadOnly);
    }
    let pid = process.pid();
    if !process.is_alive() {
        return Err(Error::TargetExited { pid });
    }
    check_bitness(&process)?;
    let execution = memdiver_call_sys::open_execution(pid).map_err(|error| map_open(error, pid))?;
    if !process.is_alive() {
        return Err(close_after(execution, Error::TargetExited { pid }, pid));
    }
    Ok(RemoteCaller {
        process,
        execution,
        serialization: Mutex::new(()),
        kind: TargetKind::Native,
    })
}

/// Adopts an existing handle on Linux with a short attach/verify/detach
/// handshake.
#[cfg(target_os = "linux")]
fn adopt(process: Process) -> Result<RemoteCaller, Error> {
    if !process.is_writable() {
        return Err(Error::ReadOnly);
    }
    let pid = process.pid();
    if !process.is_alive() {
        return Err(Error::TargetExited { pid });
    }
    check_bitness(&process)?;
    let attached = memdiver_call_sys::attach(pid, pid).map_err(|error| map_open(error, pid))?;
    if !process.is_alive() {
        return Err(detach_after(attached, Error::TargetExited { pid }, pid));
    }
    attached
        .detach()
        .map_err(|error| cleanup_error(error, pid))?;
    Ok(RemoteCaller {
        process,
        serialization: Mutex::new(()),
        kind: TargetKind::Native,
    })
}

/// Opens the PE-hosting process of a 32-bit Windows target under Wine.
#[cfg(target_os = "linux")]
fn open_wine_pinned(pid: u32) -> Result<RemoteCaller, Error> {
    let process = Process::open(pid).map_err(|source| Error::Open {
        pid,
        operation: "memdiver::Process::open",
        source: Box::new(source),
    })?;
    adopt_wine(process)
}

/// Wine 32-bit targets are only reachable from a native Linux host.
#[cfg(not(target_os = "linux"))]
fn open_wine_pinned(pid: u32) -> Result<RemoteCaller, Error> {
    let _ = pid;
    Err(Error::Unsupported {
        operation: "RemoteCaller::open_wine",
        reason: "Wine targets are only supported from a native Linux host",
    })
}

/// Adopts a writable handle for a 32-bit Windows PE under Wine.
#[cfg(target_os = "linux")]
fn adopt_wine(process: Process) -> Result<RemoteCaller, Error> {
    if !process.is_writable() {
        return Err(Error::ReadOnly);
    }
    let pid = process.pid();
    if !process.is_alive() {
        return Err(Error::TargetExited { pid });
    }
    memdiver_call_sys::wine32::detect(&process).map_err(|error| map_wine_error(error, pid))?;
    Ok(RemoteCaller {
        process,
        serialization: Mutex::new(()),
        kind: TargetKind::Wine32,
    })
}

/// Wine 32-bit targets are only reachable from a native Linux host.
#[cfg(not(target_os = "linux"))]
fn adopt_wine(process: Process) -> Result<RemoteCaller, Error> {
    let _ = process;
    Err(Error::Unsupported {
        operation: "RemoteCaller::new_wine",
        reason: "Wine targets are only supported from a native Linux host",
    })
}

/// Runs a validated call on Windows.
#[cfg(windows)]
fn call_pinned(
    caller: &RemoteCaller,
    function: Address,
    args: &[u64],
    options: &CallOptions,
) -> Result<u64, Error> {
    if caller.kind == TargetKind::Wine32 {
        return Err(Error::Unsupported {
            operation: "call",
            reason: "Wine targets are only supported from a native Linux host",
        });
    }
    let pid = caller.process.pid();
    let outcome = memdiver_call_sys::call(
        &caller.execution,
        &caller.process,
        function.get(),
        args,
        sys_abi(options.abi()),
        options.wide_arguments(),
    );
    finish(function, pid, outcome)
}

/// Dispatches a validated call on Linux.
#[cfg(target_os = "linux")]
fn call_pinned(
    caller: &RemoteCaller,
    function: Address,
    args: &[u64],
    options: &CallOptions,
) -> Result<u64, Error> {
    match caller.kind {
        TargetKind::Wine32 => wine32_call(caller, function, args, options),
        _ => native_call(caller, function, args, options),
    }
}

/// Runs a validated call on a native Linux target, attaching for the duration.
#[cfg(target_os = "linux")]
fn native_call(
    caller: &RemoteCaller,
    function: Address,
    args: &[u64],
    options: &CallOptions,
) -> Result<u64, Error> {
    let pid = caller.process.pid();
    let tid = options.thread().unwrap_or(pid);
    let attached = memdiver_call_sys::attach(pid, tid).map_err(|error| map_open(error, pid))?;
    // Double-liveness check: the attach pins the task, so a false result means
    // the memory handle refers to an instance that has already exited.
    if !caller.process.is_alive() {
        return Err(detach_after(attached, Error::TargetExited { pid }, pid));
    }
    let outcome = attached.call(&caller.process, function.get(), args);
    finish(function, pid, outcome)
}

/// Runs a validated call on a 32-bit Windows PE under Wine.
#[cfg(target_os = "linux")]
fn wine32_call(
    caller: &RemoteCaller,
    function: Address,
    args: &[u64],
    options: &CallOptions,
) -> Result<u64, Error> {
    let pid = caller.process.pid();
    let tid = options.thread().unwrap_or(pid);
    let attached =
        memdiver_call_sys::wine32::attach(pid, tid).map_err(|error| map_open(error, pid))?;
    if !caller.process.is_alive() {
        return Err(detach_wine32_after(
            attached,
            Error::TargetExited { pid },
            pid,
        ));
    }
    let spec = memdiver_call_sys::wine32::CallSpec {
        function: function.get(),
        args,
        abi: wine_abi(options.abi()),
        wide_arguments: options.wide_arguments(),
        safe_point: options.safe_point().map(Address::get),
        timeout: options.safe_point_timeout(),
    };
    let outcome = attached.call(&caller.process, &spec);
    finish(function, pid, outcome)
}

/// Maps a `memdiver-call` ABI choice to a 32-bit Windows convention.
#[cfg(target_os = "linux")]
fn wine_abi(abi: CallAbi) -> memdiver_call_sys::wine32::WineAbi {
    match abi {
        CallAbi::Auto | CallAbi::Cdecl => memdiver_call_sys::wine32::WineAbi::Cdecl,
        CallAbi::Stdcall => memdiver_call_sys::wine32::WineAbi::Stdcall,
        CallAbi::Thiscall => memdiver_call_sys::wine32::WineAbi::Thiscall,
        CallAbi::Fastcall => memdiver_call_sys::wine32::WineAbi::Fastcall,
    }
}

/// Maps a `memdiver-call-sys` ABI choice.
#[cfg(windows)]
fn sys_abi(abi: CallAbi) -> memdiver_call_sys::Abi {
    match abi {
        CallAbi::Auto => memdiver_call_sys::Abi::Auto,
        CallAbi::Cdecl => memdiver_call_sys::Abi::Cdecl,
        CallAbi::Stdcall => memdiver_call_sys::Abi::Stdcall,
        CallAbi::Thiscall => memdiver_call_sys::Abi::Thiscall,
        CallAbi::Fastcall => memdiver_call_sys::Abi::Fastcall,
    }
}

/// Verifies that the host and target have the same bitness.
fn check_bitness(process: &Process) -> Result<(), Error> {
    let width = process.pointer_width().map_err(|source| Error::Memory {
        operation: "Process::pointer_width",
        source: Box::new(source),
    })?;
    let expected = if cfg!(target_arch = "x86_64") {
        PointerWidth::Bits64
    } else {
        PointerWidth::Bits32
    };
    if width != expected {
        return Err(Error::Unsupported {
            operation: "RemoteCaller",
            reason: "the target bitness differs from the host bitness",
        });
    }
    Ok(())
}

/// Builds the per-argument wide flag, validating the declared indices.
fn wide_flags(argument_count: usize, options: &CallOptions) -> Result<Vec<bool>, Error> {
    let mut wide = vec![false; argument_count];
    for &index in options.wide_arguments() {
        let Some(slot) = wide.get_mut(index) else {
            return Err(Error::InvalidArgument {
                index,
                reason: "the wide-argument index is out of range",
            });
        };
        if *slot {
            return Err(Error::InvalidArgument {
                index,
                reason: "the wide-argument index is repeated",
            });
        }
        *slot = true;
    }
    Ok(wide)
}

/// Validates the ABI and thread selection before any operating-system call.
fn validate_abi(options: &CallOptions, pid: u32) -> Result<(), Error> {
    #[cfg(target_arch = "x86_64")]
    if options.abi() != CallAbi::Auto {
        return Err(Error::Unsupported {
            operation: "call",
            reason: "only the platform default ABI is supported on x86_64",
        });
    }
    #[cfg(target_arch = "x86")]
    let _ = options.abi();

    match options.thread() {
        None => Ok(()),
        Some(tid) => {
            #[cfg(target_os = "linux")]
            {
                if tid != pid {
                    return Err(Error::Unsupported {
                        operation: "call",
                        reason: "only the main thread (TID == PID) is supported",
                    });
                }
                Ok(())
            }
            #[cfg(windows)]
            {
                let _ = (tid, pid);
                Err(Error::Unsupported {
                    operation: "call",
                    reason: "thread selection is not supported on Windows",
                })
            }
        }
    }
}

/// Turns a call outcome and any cleanup failure into the public result.
fn finish(function: Address, pid: u32, outcome: CallOutcome) -> Result<u64, Error> {
    match outcome.cleanup {
        None => outcome
            .result
            .map_err(|error| map_call_error(error, function, pid)),
        Some(cleanup) => {
            let call = outcome
                .result
                .err()
                .map(|error| Box::new(map_call_error(error, function, pid)));
            Err(Error::Cleanup {
                function: Some(function),
                call,
                cleanup: Box::new(map_cleanup_error(cleanup, pid)),
            })
        }
    }
}

/// Maps a failure to open the execution resource or memory handle.
fn map_open(error: SysError, pid: u32) -> Error {
    match error {
        SysError::TargetExited => Error::TargetExited { pid },
        SysError::Unsupported { operation, reason } => Error::Unsupported { operation, reason },
        SysError::Open(failure) | SysError::Platform(failure) => Error::Open {
            pid,
            operation: failure.operation(),
            source: Box::new(PlatformError::new(failure.code())),
        },
        other => map_call_error(other, Address::NULL, pid),
    }
}

/// Maps a failure while detecting a Wine target.
#[cfg(target_os = "linux")]
fn map_wine_error(error: SysError, pid: u32) -> Error {
    match error {
        SysError::Unsupported { operation, reason } => Error::Unsupported { operation, reason },
        SysError::Inspect { operation, source } => Error::Memory { operation, source },
        SysError::TargetExited => Error::TargetExited { pid },
        SysError::Platform(failure) | SysError::Open(failure) => Error::Open {
            pid,
            operation: failure.operation(),
            source: Box::new(PlatformError::new(failure.code())),
        },
        other => map_call_error(other, Address::NULL, pid),
    }
}

/// Maps a call failure.
fn map_call_error(error: SysError, function: Address, pid: u32) -> Error {
    match error {
        SysError::Unsupported { operation, reason } => Error::Unsupported { operation, reason },
        SysError::InvalidAddress { address, reason } => Error::InvalidAddress {
            address: Address::new(address),
            reason,
        },
        SysError::InvalidArgument { index, reason } => Error::InvalidArgument { index, reason },
        SysError::Open(failure) | SysError::Platform(failure) => Error::Platform {
            operation: failure.operation(),
            source: PlatformError::new(failure.code()),
        },
        SysError::TargetExited => Error::TargetExited { pid },
        SysError::SafePointTimeout { address, timeout } => Error::SafePointTimeout {
            address: Address::new(address),
            timeout,
        },
        SysError::CallFailed(status) => Error::CallFailed {
            function,
            status: status_from_sys(status),
        },
        SysError::Inspect { operation, source } => Error::Memory { operation, source },
        SysError::Leak { operation, reason } => Error::Leaked { operation, reason },
    }
}

/// Maps a cleanup failure.
fn map_cleanup_error(error: SysError, pid: u32) -> Error {
    match error {
        SysError::Leak { operation, reason } => Error::Leaked { operation, reason },
        SysError::TargetExited => Error::TargetExited { pid },
        SysError::Platform(failure) | SysError::Open(failure) => Error::Platform {
            operation: failure.operation(),
            source: PlatformError::new(failure.code()),
        },
        other => map_call_error(other, Address::NULL, pid),
    }
}

/// Builds a cleanup error for a failure that happens between calls.
#[cfg(target_os = "linux")]
fn cleanup_error(error: SysError, pid: u32) -> Error {
    Error::Cleanup {
        function: None,
        call: None,
        cleanup: Box::new(map_cleanup_error(error, pid)),
    }
}

/// Closes an execution handle and keeps both the original failure and any
/// close failure.
#[cfg(windows)]
fn close_after(execution: memdiver_call_sys::Execution, failure: Error, pid: u32) -> Error {
    match execution.close() {
        Ok(()) => failure,
        Err(cleanup) => Error::Cleanup {
            function: None,
            call: Some(Box::new(failure)),
            cleanup: Box::new(map_cleanup_error(cleanup, pid)),
        },
    }
}

/// Detaches and keeps both the original failure and any detach failure.
#[cfg(target_os = "linux")]
fn detach_after(attached: memdiver_call_sys::Attached, failure: Error, pid: u32) -> Error {
    match attached.detach() {
        Ok(()) => failure,
        Err(cleanup) => Error::Cleanup {
            function: None,
            call: Some(Box::new(failure)),
            cleanup: Box::new(map_cleanup_error(cleanup, pid)),
        },
    }
}

/// Detaches a Wine 32-bit attachment and keeps both failures.
#[cfg(target_os = "linux")]
fn detach_wine32_after(
    attached: memdiver_call_sys::wine32::Attached,
    failure: Error,
    pid: u32,
) -> Error {
    match attached.detach() {
        Ok(()) => failure,
        Err(cleanup) => Error::Cleanup {
            function: None,
            call: Some(Box::new(failure)),
            cleanup: Box::new(map_cleanup_error(cleanup, pid)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CallStatus;
    use memdiver_call_sys::OsFailure;

    const FUNCTION: Address = Address::new(0x1000);

    fn platform(operation: &'static str, code: i64) -> SysError {
        SysError::Platform(OsFailure::new(operation, code))
    }

    #[test]
    fn successful_call_without_cleanup_is_ok() {
        let outcome = CallOutcome {
            result: Ok(42),
            cleanup: None,
        };
        assert_eq!(finish(FUNCTION, 7, outcome).expect("ok"), 42);
    }

    #[test]
    fn cleanup_failure_never_returns_ok() {
        let outcome = CallOutcome {
            result: Ok(42),
            cleanup: Some(platform("PTRACE_DETACH", 5)),
        };
        let error = finish(FUNCTION, 7, outcome).expect_err("cleanup failure");
        match error {
            Error::Cleanup { call, cleanup, .. } => {
                assert!(call.is_none());
                assert!(matches!(*cleanup, Error::Platform { .. }));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn call_and_cleanup_failures_are_both_kept() {
        let outcome = CallOutcome {
            result: Err(SysError::CallFailed(memdiver_call_sys::CallStatus::Signal(
                11,
            ))),
            cleanup: Some(platform("PTRACE_DETACH", 3)),
        };
        let error = finish(FUNCTION, 7, outcome).expect_err("both failures");
        match error {
            Error::Cleanup { call, cleanup, .. } => {
                assert!(matches!(call.as_deref(), Some(Error::CallFailed { .. })));
                assert!(matches!(*cleanup, Error::Platform { .. }));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn leak_cleanup_is_reported() {
        let outcome = CallOutcome {
            result: Err(SysError::CallFailed(memdiver_call_sys::CallStatus::Exited)),
            cleanup: Some(SysError::Leak {
                operation: "VirtualFreeEx",
                reason: "thread may run",
            }),
        };
        let error = finish(FUNCTION, 7, outcome).expect_err("leak");
        match error {
            Error::Cleanup { cleanup, .. } => {
                assert!(matches!(*cleanup, Error::Leaked { .. }));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn open_errors_keep_the_raw_code() {
        let error = map_open(platform("PTRACE_SEIZE", 1), 7);
        match error {
            Error::Open {
                pid,
                operation,
                source,
            } => {
                assert_eq!(pid, 7);
                assert_eq!(operation, "PTRACE_SEIZE");
                assert_eq!(
                    source.downcast_ref::<PlatformError>().map(|e| e.code()),
                    Some(1)
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn invalid_addresses_keep_the_offending_value() {
        let error = map_call_error(
            SysError::InvalidAddress {
                address: 0x2000,
                reason: "not executable",
            },
            FUNCTION,
            7,
        );
        match error {
            Error::InvalidAddress { address, reason } => {
                assert_eq!(address, Address::new(0x2000));
                assert_eq!(reason, "not executable");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn safe_point_timeouts_are_mapped() {
        let error = map_call_error(
            SysError::SafePointTimeout {
                address: 0x0040_1000,
                timeout: std::time::Duration::from_millis(100),
            },
            FUNCTION,
            7,
        );
        match error {
            Error::SafePointTimeout { address, timeout } => {
                assert_eq!(address, Address::new(0x0040_1000));
                assert_eq!(timeout, std::time::Duration::from_millis(100));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn call_statuses_are_translated() {
        let error = map_call_error(
            SysError::CallFailed(memdiver_call_sys::CallStatus::ThreadExit(9)),
            FUNCTION,
            7,
        );
        match error {
            Error::CallFailed {
                function,
                status: CallStatus::ThreadExit(9),
            } => assert_eq!(function, FUNCTION),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn caller_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RemoteCaller>();
    }
}
