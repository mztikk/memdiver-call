//! The pinned remote caller and its pinning protocol.

use std::fmt;
use std::sync::Mutex;

use memdiver::{Address, PointerWidth, Process};
use memdiver_call_sys::{CallOutcome, SysError};

use crate::error::{Error, PlatformError, status_from_sys};
use crate::options::{CallAbi, CallOptions};

/// Maximum number of argument slots in v1.
const MAX_ARGUMENTS: usize = 6;

/// A pinned target process plus the execution resource needed to call into it.
///
/// The caller keeps a writable [`memdiver::Process`] for all memory access and,
/// on Windows, a process handle opened with `PROCESS_CREATE_THREAD` and the
/// other rights the mechanism needs. On Linux no trace is kept between calls:
/// each call attaches to the main thread, runs, restores the thread state, and
/// detaches.
///
/// The type is `Send + Sync`, but calls on one instance are serialized with an
/// internal mutex. Two separate callers for the same target are not
/// coordinated; on Linux the second attach fails with `EBUSY` and is reported,
/// not retried.
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
}

impl RemoteCaller {
    /// Opens `pid` and pins it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Open`] when the execution resource or the `memdiver`
    /// handle cannot be opened, [`Error::TargetExited`] when the target exits
    /// during setup, [`Error::Unsupported`] when the target's bitness differs
    /// from the host, and [`Error::Cleanup`] when a resource opened during
    /// setup cannot be released after a failure.
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
    /// alive, [`Error::Unsupported`] for a bitness mismatch, and
    /// [`Error::Open`]/[`Error::Cleanup`] for resource failures.
    pub fn new(process: Process) -> Result<Self, Error> {
        adopt(process)
    }

    /// Returns the underlying memory handle.
    #[must_use]
    pub fn process(&self) -> &Process {
        &self.process
    }

    /// Calls `function` with up to six `u64` argument slots.
    ///
    /// Pointer arguments are raw target addresses. The caller owns the
    /// pointed-to memory and its lifetime; v1 does not copy strings, structs, or
    /// buffers into the target.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] for an unsupported ABI, thread, or host
    /// architecture, [`Error::InvalidArgument`] for more than six arguments or
    /// a value that does not fit the target, [`Error::InvalidAddress`] when the
    /// function is not in an executable live region, [`Error::TargetExited`]
    /// when the target is gone, [`Error::CallFailed`] when the call did not
    /// return a normal result, and [`Error::Cleanup`] when target state could
    /// not be restored or resources could not be released. All validation
    /// errors are returned before the target is touched.
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
    /// # Errors
    ///
    /// Returns [`Error::ExportNotFound`] when the module is loaded but does not
    /// export the name, [`Error::Memory`] when resolution itself fails, and the
    /// same errors as [`RemoteCaller::call`]. In particular, a data export
    /// returns [`Error::InvalidAddress`].
    pub fn call_export(
        &self,
        module: &str,
        export: &str,
        args: &[u64],
        options: &CallOptions,
    ) -> Result<u64, Error> {
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
            for (index, argument) in args.iter().enumerate() {
                if *argument > u64::from(u32::MAX) {
                    return Err(Error::InvalidArgument {
                        index,
                        reason: "the value does not fit in a 32-bit argument slot",
                    });
                }
            }
        }
        match self.process.region_at(function) {
            Ok(Some(region)) if region.is_executable() => Ok(()),
            Ok(Some(_)) => Err(Error::InvalidAddress {
                address: function,
                reason: "the address is not in an executable region",
            }),
            Ok(None) => Err(Error::InvalidAddress {
                address: function,
                reason: "the address is not in a live region",
            }),
            Err(source) => Err(Error::Memory {
                operation: "Process::region_at",
                source: Box::new(source),
            }),
        }
    }
}

impl fmt::Debug for RemoteCaller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteCaller")
            .field("pid", &self.process.pid())
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
    let pid = caller.process.pid();
    let outcome = memdiver_call_sys::call(
        &caller.execution,
        &caller.process,
        function.get(),
        args,
        sys_abi(options.abi()),
    );
    finish(function, pid, outcome)
}

/// Runs a validated call on Linux, attaching for the duration.
#[cfg(target_os = "linux")]
fn call_pinned(
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
            operation: "RemoteCaller::open",
            reason: "the target bitness differs from the host bitness",
        });
    }
    Ok(())
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
