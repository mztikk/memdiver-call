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
//! # Wine 32-bit targets
//!
//! [`RemoteCaller::open_wine`] calls into a 32-bit Windows PE that Wine hosts
//! on this Linux machine. Wine executes the PE natively in 32-bit
//! compatibility mode and maps it at its Windows virtual addresses, so a
//! normal `ptrace` attachment can redirect the thread.
//!
//! * The PID must be the **PE-hosting process** (the one whose command line is
//!   the `.exe`), not the `wine` launcher.
//! * A caller that spawns Wine should set `PR_SET_CHILD_SUBREAPER` before
//!   spawning. Wine reparents the PE host, and under Yama `ptrace_scope = 1`
//!   only descendants are traceable. Processes started by Steam/Proton may
//!   live in a different PID namespace and cannot be reached from outside
//!   their container.
//! * A thread stopped inside a Wine syscall is in 64-bit mode (`CS = 0x33`);
//!   only 32-bit-mode stops (`CS = 0x23`) can be redirected. Use
//!   [`CallOptions::with_safe_point`] with an instruction the main thread
//!   reaches regularly, for example the instruction after `SwapBuffers`
//!   returns or a per-frame tick entry. The backend waits for a hardware
//!   breakpoint there, bounded by
//!   [`CallOptions::with_safe_point_timeout`], and reuses the same breakpoint
//!   for the return.
//! * Arguments are 32-bit values: each `u64` slot must fit in 32 bits. The
//!   result is `EDX:EAX`; for a 32-bit return value only the low half is
//!   meaningful. All 32-bit conventions are available.
//! * PE exports cannot be resolved by `memdiver` on Linux, so `call_export`
//!   returns [`Error::Unsupported`]; pass the function address to `call`.
//! * C++ exceptions or `longjmp` unwinding through the synthetic frame are
//!   unsupported. The call runs on the game's main thread under its locks and
//!   thread-local state, which is the caller's risk.
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

pub use caller::{RemoteCaller, TargetKind};
pub use error::{CallStatus, Error, PlatformError};
pub use options::{CallAbi, CallOptions};
