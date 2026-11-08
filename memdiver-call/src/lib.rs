//! Call functions inside another local process.
//!
//! `memdiver-call` invokes a function that lives in another process on the same
//! machine and returns its integer result. It is built on the public
//! [`memdiver`] facade: process pinning, memory reads and writes, regions,
//! modules, and exports all go through `memdiver`, and `memdiver` is not
//! modified or reimplemented.
//!
//! This is the external-memory-tool meaning of "remote call", not network RPC
//! and not `.so`/DLL injection for its own sake.
//!
//! # How it works
//!
//! | Platform | Mechanism |
//! |----------|-----------|
//! | Linux `x86_64` | `ptrace` attaches to the main thread, a hardware execution breakpoint is placed at the interrupted instruction, `RIP`/`RSP`/argument registers are redirected, and the full thread state is restored afterwards. No target code is written. |
//! | Windows `x86_64` and `x86` | A generated machine-code stub is written into a remote `PAGE_READWRITE` page, changed to `PAGE_EXECUTE_READ`, and run by `CreateRemoteThread`. The stub stores the result and a completion flag in a separate allocation. |
//!
//! Both mechanisms are invasive. On Linux the target shows a `TracerPid`, one
//! thread is stopped and redirected, and an in-flight syscall can return
//! `EINTR`. On Windows the target gains a thread and loader notifications fire.
//!
//! # Supported matrix
//!
//! - Host and target both `x86_64` on Linux or Windows, or both `x86` on
//!   Windows. Cross-bitness and WOW64 return [`Error::Unsupported`].
//! - Up to six integer or pointer arguments, passed in `u64` slots.
//! - Integer or pointer return value, returned as `u64`.
//! - One synchronous call that runs to completion. There is no timeout and no
//!   cancellation.
//! - A writable [`memdiver::Process`]. Read-only handles are rejected before
//!   any operating-system execution resource is opened.
//! - On `x86_64`, only [`CallAbi::Auto`] is valid. On Windows `x86`,
//!   `cdecl`, `stdcall`, `thiscall`, and `fastcall` are available.
//!
//! Everything else returns [`Error::Unsupported`] or is not part of the API.
//!
//! # Safety
//!
//! The functions are safe Rust with respect to the caller's own memory, but a
//! call can **crash or corrupt the target**. The library cannot validate a
//! function signature, a calling convention, or the side effects of the called
//! code. Pointer arguments are raw target addresses; the caller owns the
//! pointed-to memory and its lifetime. The target may deadlock if the called
//! function needs a lock held by a thread that is stopped or by the calling
//! thread.
//!
//! Use this only on processes you own or are explicitly authorized to inspect.
//!
//! # Requirements
//!
//! - Linux: permission to `ptrace` the target. Under Yama
//!   `kernel.yama.ptrace_scope = 1` a normal user can trace a descendant; other
//!   targets need `CAP_SYS_PTRACE` or `PR_SET_PTRACER`. CET shadow stack
//!   (`SHSTK`) targets are refused.
//! - Windows: `PROCESS_CREATE_THREAD`, `PROCESS_QUERY_INFORMATION`,
//!   `PROCESS_VM_OPERATION`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, and
//!   `PROCESS_SYNCHRONIZE` on the target.
//!
//! # Example
//!
//! ```no_run
//! use memdiver::Address;
//! use memdiver_call::{CallOptions, RemoteCaller};
//!
//! # fn main() -> Result<(), memdiver_call::Error> {
//! let caller = RemoteCaller::open(4242)?;
//! let result = caller.call(Address::new(0x1400_0100), &[1, 2], &CallOptions::new())?;
//! println!("remote function returned {result}");
//! # Ok(())
//! # }
//! ```
//!
//! # Limitations
//!
//! No timeout, cancellation, asynchronous calls, or thread hijacking; no
//! floating-point, SIMD, struct-by-value, variadic, or C++ `thiscall` on
//! `x86_64` support; no general remote allocation or string/struct marshalling;
//! no ARM64; no Linux thread selection beyond the main thread; no
//! `WOW64`/cross-bitness calls. A call that never returns hangs the caller.
//! On Windows the generated stub has no unwind metadata, so C++ exceptions
//! must not cross it. Native Windows Control Flow Guard and CET behaviour is
//! not verified by this project's local test suite.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod caller;
mod error;
mod options;

pub use caller::RemoteCaller;
pub use error::{CallStatus, Error, PlatformError};
pub use options::{CallAbi, CallOptions};
