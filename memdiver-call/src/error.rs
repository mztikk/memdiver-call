//! The error type returned by remote calls.
//!
//! The variants keep the operation, the raw operating-system code, and the
//! remote address that were involved. A cleanup failure is reported separately
//! from a call failure so one never hides the other.

use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

use memdiver::Address;

/// A raw operating-system error code.
///
/// On Linux this is the `errno` value of the failed call. On Windows it is the
/// value returned by `GetLastError`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlatformError {
    code: i64,
}

impl PlatformError {
    pub(crate) const fn new(code: i64) -> Self {
        Self { code }
    }

    /// Returns the raw `errno` (Linux) or `GetLastError` (Windows) value.
    #[must_use]
    pub const fn code(self) -> i64 {
        self.code
    }
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "operating-system error {}", self.code)
    }
}

impl StdError for PlatformError {}

/// How a call ended without producing a normal integer result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CallStatus {
    /// The remote thread exited with this non-zero code before the generated
    /// stub could report a result.
    ThreadExit(u32),
    /// The target stopped with this signal, and forwarding it did not lead
    /// back to the expected breakpoint.
    Signal(i32),
    /// The target process exited while the call was in flight.
    Exited,
    /// The remote thread finished, but the completion flag was never written.
    ///
    /// This happens when the called function terminates its own thread instead
    /// of returning through the stub.
    NoCompletion,
    /// The platform mechanism reported a status this version does not know.
    ///
    /// The enum is non-exhaustive; new platform statuses are added without a
    /// breaking release.
    Other,
}

impl fmt::Display for CallStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ThreadExit(code) => {
                write!(
                    f,
                    "the remote thread exited with code {code} before reporting a result"
                )
            }
            Self::Signal(signal) => {
                write!(
                    f,
                    "the target did not return to the breakpoint (last signal {signal})"
                )
            }
            Self::Exited => f.write_str("the target process exited during the call"),
            Self::NoCompletion => {
                f.write_str("the remote thread returned but never reported completion")
            }
            Self::Other => f.write_str("the platform reported an unrecognized call status"),
        }
    }
}

/// The error type returned by [`crate::RemoteCaller`].
///
/// The enum is non-exhaustive so new failure modes can be added without a
/// breaking release.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Opening the execution resource or the memory handle failed.
    Open {
        /// PID that could not be opened.
        pid: u32,
        /// Operation that failed.
        operation: &'static str,
        /// Underlying error, which carries the raw platform code when the
        /// failure came from an operating-system call.
        source: Box<dyn StdError + Send + Sync>,
    },
    /// The memory handle was opened read-only.
    ///
    /// The remote call is rejected before any execution resource is opened.
    ReadOnly,
    /// The target exited, or its PID was reused, before or during the call.
    TargetExited {
        /// PID of the target.
        pid: u32,
    },
    /// The target did not reach the supplied safe point in time.
    ///
    /// This is specific to a native Linux caller targeting a 32-bit Windows
    /// PE under Wine. The call was not attempted.
    SafePointTimeout {
        /// Safe-point address that was waited for.
        address: Address,
        /// How long the wait was allowed to take.
        timeout: Duration,
    },
    /// The platform cannot perform this call.
    Unsupported {
        /// Operation that is unsupported.
        operation: &'static str,
        /// Why it is unsupported.
        reason: &'static str,
    },
    /// A function, return, or stack address is not usable.
    InvalidAddress {
        /// Address that was rejected.
        address: Address,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// An argument value is not usable for this call.
    InvalidArgument {
        /// Zero-based argument index.
        index: usize,
        /// Why the value was rejected.
        reason: &'static str,
    },
    /// An operating-system call failed.
    Platform {
        /// Operation that failed.
        operation: &'static str,
        /// Raw platform error code.
        source: PlatformError,
    },
    /// Inspecting or accessing the target through `memdiver` failed.
    Memory {
        /// `memdiver` operation that failed.
        operation: &'static str,
        /// Underlying `memdiver` error.
        source: Box<dyn StdError + Send + Sync>,
    },
    /// [`crate::RemoteCaller::call_export`] did not find the named export.
    ExportNotFound {
        /// Module name that was searched.
        module: String,
        /// Export name that was searched.
        export: String,
    },
    /// The call ran but did not produce a normal integer result.
    CallFailed {
        /// Function that was called.
        function: Address,
        /// How the call ended.
        status: CallStatus,
    },
    /// Restoring the target state or releasing resources failed.
    ///
    /// A cleanup failure is always an error, even when the call itself
    /// succeeded. When both failed, `call` keeps the primary failure — the
    /// call failure for a call, or the setup failure for `open`/`new` — and
    /// `cleanup` keeps the cleanup failure.
    Cleanup {
        /// Function that was called, when the failure happened during a call.
        function: Option<Address>,
        /// The failure that triggered cleanup, when it also failed: the call
        /// failure for a call, or the setup failure for `open`/`new`.
        call: Option<Box<Error>>,
        /// The cleanup failure.
        cleanup: Box<Error>,
    },
    /// Remote memory was deliberately abandoned in the target.
    ///
    /// The mechanism could not prove that a remote thread had stopped and
    /// therefore refused to free memory the thread may still be using. The
    /// target leaks the allocation.
    Leaked {
        /// Operation that was skipped.
        operation: &'static str,
        /// Why it was skipped.
        reason: &'static str,
    },
    /// The internal serialization mutex was poisoned by a panic.
    ///
    /// A call is never reported as successful after this error.
    Poisoned,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open {
                pid,
                operation,
                source,
            } => write!(f, "failed to open {operation} for process {pid}: {source}"),
            Self::ReadOnly => f.write_str(
                "the process handle is read-only; reopen it with memdiver::Process::open",
            ),
            Self::TargetExited { pid } => {
                write!(f, "process {pid} exited or its pid was reused")
            }
            Self::SafePointTimeout { address, timeout } => write!(
                f,
                "the target did not reach the safe point {address} within {timeout:?}"
            ),
            Self::Unsupported { operation, reason } => {
                write!(f, "{operation} is unsupported: {reason}")
            }
            Self::InvalidAddress { address, reason } => {
                write!(f, "invalid address {address}: {reason}")
            }
            Self::InvalidArgument { index, reason } => {
                write!(f, "invalid argument {index}: {reason}")
            }
            Self::Platform { operation, source } => {
                write!(f, "{operation} failed: {source}")
            }
            Self::Memory { operation, source } => {
                write!(f, "{operation} failed: {source}")
            }
            Self::ExportNotFound { module, export } => {
                write!(f, "module {module:?} does not export {export:?}")
            }
            Self::CallFailed { function, status } => {
                write!(f, "call to {function} failed: {status}")
            }
            Self::Cleanup {
                function,
                call,
                cleanup,
            } => {
                match function {
                    Some(address) => write!(
                        f,
                        "failed to restore the target after calling {address}: {cleanup}"
                    )?,
                    None => write!(f, "failed to restore the target state: {cleanup}")?,
                }
                if let Some(call) = call {
                    write!(f, " (the preceding operation also failed: {call})")?;
                }
                Ok(())
            }
            Self::Leaked { operation, reason } => {
                write!(f, "skipped {operation} because {reason}")
            }
            Self::Poisoned => f.write_str("the remote caller's serialization lock was poisoned"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Open { source, .. } => Some(source.as_ref()),
            Self::Platform { source, .. } => Some(source),
            Self::Memory { source, .. } => Some(source.as_ref()),
            Self::Cleanup { cleanup, .. } => Some(cleanup.as_ref()),
            _ => None,
        }
    }
}

/// Converts the platform status into the public status.
pub(crate) fn status_from_sys(status: memdiver_call_sys::CallStatus) -> CallStatus {
    match status {
        memdiver_call_sys::CallStatus::ThreadExit(code) => CallStatus::ThreadExit(code),
        memdiver_call_sys::CallStatus::Signal(signal) => CallStatus::Signal(signal),
        memdiver_call_sys::CallStatus::Exited => CallStatus::Exited,
        memdiver_call_sys::CallStatus::NoCompletion => CallStatus::NoCompletion,
        _ => CallStatus::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_display_keeps_both_failures() {
        let call = Error::CallFailed {
            function: Address::new(0x1000),
            status: CallStatus::Signal(11),
        };
        let cleanup = Error::Platform {
            operation: "PTRACE_DETACH",
            source: PlatformError::new(5),
        };
        let error = Error::Cleanup {
            function: Some(Address::new(0x1000)),
            call: Some(Box::new(call)),
            cleanup: Box::new(cleanup),
        };
        let text = error.to_string();
        assert!(text.contains("failed to restore"));
        assert!(text.contains("the preceding operation also failed"));
        assert!(text.contains("PTRACE_DETACH"));
        assert!(error.source().is_some());
    }

    #[test]
    fn platform_display_includes_the_raw_code() {
        let error = Error::Platform {
            operation: "CreateRemoteThread",
            source: PlatformError::new(5),
        };
        assert_eq!(
            error.to_string(),
            "CreateRemoteThread failed: operating-system error 5"
        );
        assert_eq!(PlatformError::new(5).code(), 5);
    }

    #[test]
    fn statuses_have_explanations() {
        assert!(CallStatus::ThreadExit(7).to_string().contains('7'));
        assert!(CallStatus::Signal(11).to_string().contains("11"));
        assert!(CallStatus::Exited.to_string().contains("exited"));
        assert!(CallStatus::NoCompletion.to_string().contains("completion"));
        assert!(CallStatus::Other.to_string().contains("unrecognized"));
    }
}
