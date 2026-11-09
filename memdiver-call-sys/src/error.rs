//! Errors reported by the platform mechanism.

use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

/// The outcome of one remote-call attempt.
///
/// The call result and a cleanup failure are reported separately so that a
/// failure to restore the target never hides a failed call, and a successful
/// call never becomes `Ok` when the target was left in a modified state.
#[derive(Debug)]
pub struct CallOutcome {
    /// The call result, or the reason the call failed.
    pub result: Result<u64, SysError>,
    /// A failure that happened while restoring target state or releasing
    /// resources.
    ///
    /// Cleanup is attempted on every path. When this is `Some`, the caller
    /// must report the call as failed even if [`CallOutcome::result`] is
    /// `Ok`.
    pub cleanup: Option<SysError>,
}

/// How a call ended without producing a normal integer result.
///
/// The enum is non-exhaustive so new platform statuses can be added without a
/// breaking release; `memdiver-call` maps an unknown status to its `Other`.
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
    /// This happens when the called function terminates its own thread (for
    /// example with `ExitThread`) instead of returning through the stub, so
    /// stale or zeroed result memory must not be trusted.
    NoCompletion,
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
        }
    }
}

/// An operating-system call failure with the raw platform error code.
///
/// On Linux [`OsFailure::code`] is the `errno` value. On Windows it is the
/// value returned by `GetLastError`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OsFailure {
    operation: &'static str,
    code: i64,
}

impl OsFailure {
    /// Creates a failure record from an operation name and a raw OS code.
    #[must_use]
    pub const fn new(operation: &'static str, code: i64) -> Self {
        Self { operation, code }
    }

    /// Returns the name of the operating-system call that failed.
    #[must_use]
    pub const fn operation(self) -> &'static str {
        self.operation
    }

    /// Returns the raw operating-system error code.
    #[must_use]
    pub const fn code(self) -> i64 {
        self.code
    }
}

impl fmt::Display for OsFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} failed with OS code {}", self.operation, self.code)
    }
}

impl StdError for OsFailure {}

/// A failure inside the platform mechanism.
///
/// This type is internal to the `memdiver-call` family: callers see
/// [`memdiver_call::Error`] instead. It is public because the safe crate is a
/// separate package.
///
/// [`memdiver_call::Error`]: https://docs.rs/memdiver-call
#[derive(Debug)]
pub enum SysError {
    /// The mechanism cannot perform this call.
    Unsupported {
        /// Operation that is unsupported.
        operation: &'static str,
        /// Why it is unsupported.
        reason: &'static str,
    },
    /// An address is not usable for the call.
    InvalidAddress {
        /// Address that was rejected.
        address: u64,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// An argument value is not usable for the call.
    InvalidArgument {
        /// Zero-based argument index.
        index: usize,
        /// Why the value was rejected.
        reason: &'static str,
    },
    /// Opening the execution resource failed.
    Open(OsFailure),
    /// The target exited or its PID was reused.
    TargetExited,
    /// The target did not reach the safe point within the allotted time.
    SafePointTimeout {
        /// Safe-point address that was waited for.
        address: u64,
        /// How long the wait was allowed to take.
        timeout: Duration,
    },
    /// An operating-system call failed.
    Platform(OsFailure),
    /// The call ran but did not finish normally.
    CallFailed(CallStatus),
    /// Inspecting the target through `memdiver` failed.
    Inspect {
        /// `memdiver` operation that failed.
        operation: &'static str,
        /// Underlying error.
        source: Box<dyn StdError + Send + Sync>,
    },
    /// Remote memory was intentionally abandoned.
    ///
    /// This is reported when the mechanism cannot prove that a remote thread
    /// has stopped and therefore refuses to free memory the thread may still
    /// use. The target leaks the allocation; the caller must report it.
    Leak {
        /// Operation that was skipped.
        operation: &'static str,
        /// Why it was skipped.
        reason: &'static str,
    },
}

impl fmt::Display for SysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported { operation, reason } => {
                write!(f, "{operation} is unsupported: {reason}")
            }
            Self::InvalidAddress { address, reason } => {
                write!(f, "invalid address {address:#x}: {reason}")
            }
            Self::InvalidArgument { index, reason } => {
                write!(f, "invalid argument {index}: {reason}")
            }
            Self::Open(failure) => write!(f, "failed to open the execution resource: {failure}"),
            Self::TargetExited => f.write_str("the target process exited or its pid was reused"),
            Self::SafePointTimeout { address, timeout } => write!(
                f,
                "the target did not reach the safe point {address:#x} within {timeout:?}"
            ),
            Self::Platform(failure) => failure.fmt(f),
            Self::CallFailed(status) => write!(f, "the remote call failed: {status}"),
            Self::Inspect { operation, source } => write!(f, "{operation} failed: {source}"),
            Self::Leak { operation, reason } => {
                write!(f, "skipped {operation} because {reason}")
            }
        }
    }
}

impl StdError for SysError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Open(failure) | Self::Platform(failure) => Some(failure),
            Self::Inspect { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}
