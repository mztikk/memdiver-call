//! Unsafe platform mechanism for [`memdiver-call`].
//!
//! This crate owns everything that needs `unsafe`: the Linux `ptrace`
//! machinery and the Windows remote-thread machinery. It deliberately contains
//! no policy of its own beyond the mechanism invariants needed to execute a
//! request safely (argument count, address classes, and frame bounds) as
//! defense in depth. [`memdiver-call`] owns the public policy, performs the
//! user-facing validation, and maps the errors returned here.
//!
//! [`memdiver-call`]: https://docs.rs/memdiver-call
//!
//! # Supported platforms
//!
//! | Host | Mechanism |
//! |------|-----------|
//! | Linux `x86_64` | `ptrace` + a hardware execution breakpoint |
//! | Windows `x86_64` | `CreateRemoteThread` + a generated stub |
//! | Windows `x86` | `CreateRemoteThread` + a generated 32-bit stub |
//! | Linux `x86_64` → 32-bit Wine PE | `ptrace` in 32-bit compatibility mode + a safe point |
//!
//! Any other host fails to compile with an explicit diagnostic. Every
//! `unsafe` block in this crate carries a `// SAFETY:` comment naming the
//! invariant it relies on.

#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unreachable_pub)]

mod error;

#[cfg(any(target_os = "linux", test))]
mod debug;
#[cfg(any(target_os = "linux", test))]
mod frame;
#[cfg(any(target_os = "linux", test))]
mod frame_x86;
#[cfg(any(windows, test))]
mod stub;
#[cfg(any(target_arch = "x86", target_os = "linux", test))]
mod x86_args;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;
#[cfg(target_os = "linux")]
pub mod wine32;

pub use error::{CallOutcome, CallStatus, OsFailure, SysError};

#[cfg(target_os = "linux")]
pub use linux::{Attached, attach};

#[cfg(windows)]
pub use windows::{Abi, Execution, call, open_execution};

/// The maximum number of `u64` argument slots a call may use.
pub const MAX_ARGUMENTS: usize = 6;

/// Reports whether this build can execute a remote call.
///
/// This is a compile-time property: the crate fails to compile on a platform
/// where the answer would be `false`.
#[must_use]
pub const fn is_supported() -> bool {
    (cfg!(target_os = "linux") && cfg!(target_arch = "x86_64"))
        || (cfg!(windows) && (cfg!(target_arch = "x86_64") || cfg!(target_arch = "x86")))
}

#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, any(target_arch = "x86_64", target_arch = "x86"))
)))]
compile_error!(
    "memdiver-call-sys supports Linux x86_64, Windows x86_64, and Windows x86 only; \
     other host platforms are not implemented"
);

/// Collects the first of several cleanup failures without skipping the others.
#[derive(Default)]
pub(crate) struct Failures(Option<SysError>);

impl Failures {
    /// Records a failure if no earlier one was recorded.
    pub(crate) fn record(&mut self, result: Result<(), SysError>) {
        if self.0.is_none() {
            if let Err(error) = result {
                self.0 = Some(error);
            }
        }
    }

    /// Records a failure value if no earlier one was recorded.
    #[allow(dead_code)] // used by the Windows backend
    pub(crate) fn record_error(&mut self, error: Option<SysError>) {
        if self.0.is_none() {
            self.0 = error;
        }
    }

    /// Returns the first recorded failure.
    #[allow(dead_code)] // used by the Windows backend
    pub(crate) fn into_option(self) -> Option<SysError> {
        self.0
    }

    /// Returns the first recorded failure as an error.
    #[allow(dead_code)] // used by the Linux backend
    pub(crate) fn into_result(self) -> Result<(), SysError> {
        match self.0 {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
