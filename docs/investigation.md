# Remote function calls on top of memdiver

**Status:** investigation only. This document does not add a public API or
production code. The prototypes it reports on are scratch programs under the
ignored `target/` directory. A build brief for an independent implementation is
in [`remote-call-agent-prompt.md`](remote-call-agent-prompt.md).

**Scope:** “remote call” here means *invoking a function inside another local
process* — the external-memory-tool sense of the term. It is not network RPC,
not DLL/`.so` injection for its own sake.

## Contents

* [Bottom line](#bottom-line)
* [1. The question](#1-the-question)
* [2. Architecture options](#2-architecture-options)
* [3. Proposed library](#3-proposed-library)
* [4. Windows mechanism](#4-windows-mechanism)
* [5. Linux mechanism](#5-linux-mechanism)
* [6. Prototype results](#6-prototype-results)
* [7. Hard problems and decisions](#7-hard-problems-and-decisions)
* [8. Testing strategy](#8-testing-strategy)
* [9. Phases and effort](#9-phases-and-effort)
* [10. Decision](#10-decision)
* [References](#references)

## Bottom line

A remote-call library can be built **on top of `memdiver`'s existing public
API**, without changing `memdiver`. The narrow but useful v1 is:

* same-bitness `x86_64` (and later `x86`) processes,
* integer and pointer arguments, integer and pointer return values,
* one synchronous call that runs to completion,
* a writable `memdiver::Process`,
* Windows and Linux parity.

Windows uses a generated stub executed by `CreateRemoteThread`. Linux uses
`ptrace` and a **hardware execution breakpoint** at the interrupted instruction;
the callee returns to that instruction and the breakpoint stops the thread. That
design needs no executable remote allocation and no write to target code, so it
also avoids the shared-mapping and W^X problems of an `int3` patch. The
prototypes in `target/rc-on-top` exercise exactly this split:

* `memdiver` owns process discovery, pinning, reads/writes, regions, modules,
  exports, and liveness;
* the new library owns the execution resource (a Windows process handle or a
  Linux ptrace attachment), the calling-convention layout, and the call/cleanup
  state machine.

The hard parts are not “can it be done”. They are what happens when the call
goes wrong: timeouts and cancellation, target crashes, signals, deadlocks, ABI
diversity, CFG/CET/unwind metadata, cross-bitness, and the fact that the
operation is visible and invasive to the target. A production feature must
define those semantics explicitly rather than inherit them from
`CreateRemoteThread` / `ptrace` behaviour.

**Recommendation:** build a separate `memdiver-call` crate (plus a small
`memdiver-call-sys` for the platform mechanism), keep `memdiver` unchanged, and
ship the narrow v1 above. Treat timeout/cancel, thread hijacking, cross-bitness,
ARM64, general remote allocation, and non-integer ABI support as later phases.
The public `memdiver` promise — “never attaches a debugger, suspends threads, or
injects code” — stays true for `memdiver`; the new crate documents that it does
attach/trace or create a remote thread.

---

## 1. The question

`memdiver` can locate and modify target state, but it cannot **execute** a
function in the target. That matters when the only correct implementation of an
operation lives inside the target:

* allocating with the target's own allocator;
* calling a game's or application's own “use item”, “cast spell”, or “send
  chat” routine;
* resolving and invoking a C++ virtual method;
* running a callback with the target's thread-local state.

The downstream context that prompted the existing `write_code` work is an
external memory toolkit for a **32-bit** game client. That makes Windows `x86`
a likely requirement, not an afterthought.

### 1.1 What “on top of memdiver” has to mean

The new library must not become a second, competing memory-access
implementation. It should:

1. use `memdiver::Process` for all target memory reads and writes where
   possible;
2. use `memdiver`'s pinning and liveness rules instead of re-implementing them;
3. add only the execution mechanism that `memdiver` deliberately omits;
4. keep the dependency one-way: `memdiver-call` → `memdiver`, never the
   reverse.

That constraint is what makes the design tractable. `memdiver` already solves
the hard memory-identity problem (PID reuse, `execve`, partial transfers,
protection restoration); the new library only has to solve *execution identity*
and *call semantics*.

### 1.2 What the current library deliberately omits

| Capability | Linux | Windows | Needed for a remote call? |
|---|---|---|---|
| Open/pin process | yes | yes | yes |
| Read/write bytes | yes | yes | yes |
| Scoped code write | yes | yes | not with the Linux hardware-breakpoint design; Windows writes only its own stub |
| Memory regions / modules / exports | yes | yes | yes (validation and `call_export`) |
| Pointer width / liveness | yes | yes | yes |
| Enumerate or control threads | no | no | Linux: thread selection later; v1 uses the main thread |
| Allocate/free in target | no | no | Windows: the library allocates through its own handle; Linux v1 needs none |
| Attach as a debugger / trace | no | no | Linux: yes |
| Create a remote thread | no | no | Windows: yes |
| Call a target function | no | no | the feature |

The important omissions are **not** blockers:

* **Windows raw handle.** `Process` owns a pinned `HANDLE` but does not expose
  it. The new library opens its own handle with `PROCESS_CREATE_THREAD` and the
  rights it needs. `memdiver` uses its handle only for memory I/O.
* **Linux thread/TID API.** `ptrace` operates on a TID. v1 attaches the main
  thread (`TID == PID`); thread selection can be a later addition.
* **Remote allocation.** v1 accepts only integer/pointer arguments. The caller
  can place strings or structs in target memory with `memdiver::Process::write`
  and pass the address. A general allocator is a later phase.
* **Process start time / creation time.** Not exposed publicly. The library
  does not need it if it pins the execution resource *before* opening
  `memdiver`, or verifies liveness on both sides of an execution-handle open
  (see §3.4).

That last point is worth stating plainly: **the public API is sufficient for
v1's scope.** The prototypes in this document use only `Process::open`,
`pointer_width`, `is_writable`, `is_alive`, `region_at`, `write`, and
`read_value` from `memdiver`; no `memdiver` internals were needed. A later
thread-selection or general-allocation feature may still need its own
procfs/Win32 code, or a small additive `memdiver` API, but that is not a v1
blocker.

---

## 2. Architecture options

### Option A — separate crates on the public `memdiver` API (recommended)

```text
memdiver-call (safe API, #![forbid(unsafe_code)])
    ├── memdiver (façade: Process, Address, Error, ...)
    └── memdiver-call-sys (unsafe: ptrace / Win32 execution mechanism)
```

* `memdiver-call` owns `RemoteCaller`, `CallOptions`, `CallAbi`, `CallError`,
  validation, and the call/cleanup state machine. It has no FFI.
* `memdiver-call-sys` owns `ptrace`, register/FP state, `CreateRemoteThread`,
  `VirtualAllocEx`, `VirtualProtectEx`, and the generated Windows stub. It has
  no user-facing policy.
* `memdiver` is unchanged. Its “never attaches/injects” guarantee remains true.
* The new crates can version independently and publish after `memdiver`.

This is the cleanest separation and the one the prototypes validate.

### Option B — add low-level primitives to `memdiver`, then build on top

Add a borrowed raw handle (`Process::with_platform_handle`), `Process::threads`,
or `Process::allocate` to `memdiver`, and let the new library call those.

Advantages: one pinning implementation; no second `OpenProcess`; thread
selection and allocation share `memdiver`'s platform parsers. Disadvantages:
it expands `memdiver`'s public surface and audit scope, exposes OS handle
lifetime to callers, and adds API that most `memdiver` users do not need. It
also weakens the “no injection/debugger” identity unless the new APIs are
clearly separate.

### Option C — add `Process::call_function` directly to `memdiver-core`

This is the obvious in-tree extension, but it:

* contradicts the current README guarantee;
* changes handle rights (`PROCESS_CREATE_THREAD`) for every writable open, or
  needs a new access level;
* puts a large, platform-specific execution state machine into the crate that
  currently has no FFI and no thread control;
* makes remote-call failure semantics part of `memdiver`'s error enum and
  release cadence.

It is reasonable only if remote calls are declared a core `memdiver` feature.
The user's request is a *new library on top*, which points to Option A.

| Criterion | A: separate | B: upstream primitives | C: in-tree |
|---|---|---|---|
| `memdiver` unchanged | yes | partly | no |
| Keeps “never attaches/injects” | yes | yes, if opt-in | no |
| Reuses pinning | yes (public liveness rules) | yes (shared handle) | yes |
| Reuses regions/modules/exports | yes | yes | yes |
| Audit surface | new small crates | larger `memdiver` | largest |
| Handle rights | new handle only | shared handle changes | method behaves as new handle |
| Release cadence | independent | coupled | coupled |
| Effort | medium | medium-high | high |

**Decision: Option A.** Revisit Option B only if Linux thread selection or a
general remote allocator needs the pinned `memdiver` handle in a way the public
API cannot provide.

---

## 3. Proposed library

### 3.1 Name and layout

Working names:

* `memdiver-call` — the safe crate;
* `memdiver-call-sys` — the platform crate.

Other candidates: `memdiver-remote`, `memdiver-invoke`, `memdiver-infcall`.
“Call” is shorter; “remote” matches the user's wording but is easy to confuse
with network RPC. Verify crate-name availability before publishing.

Workspace placement (recommended): new members `crates/memdiver-call` and
`crates/memdiver-call-sys` in the same repository, with
`crates/memdiver-integration-tests` gaining a dev-dependency on `memdiver-call`
for end-to-end tests. Publication order remains `memdiver-sys`,
`memdiver-core`, `memdiver`, then `memdiver-call-sys`, `memdiver-call`.

Both new crates should inherit the workspace edition, MSRV, license, and lints.
`memdiver-call` needs its own README feature matrix (including the unsupported
cases), platform-safety section, and `cargo package --list` check before
publishing. Do not publish a crate whose README still promises “never attaches
or injects” without the remote-call exception.

### 3.2 API sketch

```rust
use memdiver::{Address, Process};

/// A calling convention for a remote function.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CallAbi {
    /// Platform default: Microsoft x64, SysV AMD64, or 32-bit cdecl.
    #[default]
    Auto,
    /// 32-bit x86 cdecl.
    Cdecl,
    /// 32-bit Windows stdcall.
    Stdcall,
    /// 32-bit Windows thiscall (`this` in ECX).
    Thiscall,
    /// 32-bit Windows fastcall (first arguments in ECX/EDX).
    Fastcall,
}

/// Options for a remote call.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct CallOptions {
    // Private fields; builder methods keep the struct non-exhaustive.
}

impl CallOptions {
    #[must_use]
    pub fn new() -> Self;
    #[must_use]
    pub fn with_abi(self, abi: CallAbi) -> Self;
    /// Linux TID to run on. `None` selects the main thread.
    /// Windows returns `Error::Unsupported` for anything but `None`.
    #[must_use]
    pub fn with_thread(self, tid: u32) -> Self;
}

/// A pinned target plus the execution resource needed to call into it.
pub struct RemoteCaller {
    // process: memdiver::Process,
    // execution: platform::Execution,
    // lock: std::sync::Mutex<()>,
}

impl RemoteCaller {
    /// Pins the execution resource first, then opens the memdiver handle.
    pub fn open(pid: u32) -> Result<Self>;

    /// Adopts an existing memdiver handle. Verifies liveness on both sides
    /// of opening the execution resource.
    pub fn new(process: Process) -> Result<Self>;

    /// The underlying memory handle.
    pub fn process(&self) -> &Process;

    /// Calls a function and returns its integer/pointer result.
    pub fn call(
        &self,
        function: Address,
        args: &[u64],
        options: &CallOptions,
    ) -> Result<u64>;

    /// Resolves a named module export with memdiver and calls it.
    pub fn call_export(
        &self,
        module: &str,
        export: &str,
        args: &[u64],
        options: &CallOptions,
    ) -> Result<u64>;
}
```

`call_export` is deliberately small: it uses
`Process::module_export(module, export)` and then `call`. It is a good example
of what “on top” buys: `memdiver` already resolves PE/ELF exports to live
addresses.

`call` is safe with respect to the caller's Rust memory, but it can crash or
corrupt the target. The docs must say that as directly as `memdiver` does for
writes: the library cannot validate a function signature, an ABI choice, or the
side effects of the called code.

### 3.3 Semantics

| Aspect | Windows | Linux |
|---|---|---|
| Execution | new remote thread | existing main thread (v1) |
| Call duration | synchronous, blocks until the thread exits | synchronous, blocks in `waitpid` |
| Argument types | integer/pointer (`u64` slots) | integer/pointer (`u64` slots) |
| Return | stub stores `RAX`/`EAX` in remote memory | `RAX` from the trap |
| Read-only handle | `Error::ReadOnly` before any OS call | same |
| Timeout | none in v1 | none in v1 |
| Cancellation | none | none |
| Target state | new thread, loader notifications, timing changes | one main thread redirected and stopped at the return breakpoint; registers/flags/FP state saved and restored |
| Unsupported | ARM64, cross-width, non-`Auto` ABI on x64 | ARM64, cross-width, non-`Auto` ABI on x64 |

| Host / target | Status |
|---|---|
| Windows `x86_64` → `x86_64` | v1 target |
| Windows `x86` → `x86` | phase 3 (the 32-bit use case) |
| Windows `x86_64` → `x86` (WOW64) | out of scope for v1; return `Unsupported` |
| Windows `x86` → `x86_64` | not possible in the normal case; `Unsupported` |
| Linux `x86_64` → `x86_64` | v1 target |
| Linux `x86_64` → `i386` compat | out of scope for v1; register layout differs |
| Linux `x86` → `x86` | possible later; lower priority |
| ARM64 (Linux or Windows) | `Unsupported` initially (LR/`BRK`/BTI/PAC design differs) |

v1 supports at most **six** arguments on `x86_64`. The prototypes validate
four register arguments plus two stack arguments on Windows and six register
arguments on Linux. The Linux frame math was also exercised with eight
arguments (two stack slots) to prove that the red-zone-safe layout is correct;
that is prototype evidence for a later expansion, not a v1 API promise. More
stack arguments are mostly layout work, but they need stack-headroom validation
and a larger frame; defer them until the basic API is stable.

Non-`Auto` ABIs on `x86_64` return `Error::Unsupported` instead of being
silently treated as aliases. On `x86`, `Auto` means `cdecl`; the caller must
state `stdcall`/`thiscall`/`fastcall` explicitly because they cannot be guessed
from an address. `Cdecl` is supported on both platforms; `stdcall`, `thiscall`,
and `fastcall` are Windows `x86` conventions and return `Unsupported` on
Linux.

### 3.4 Pinning and identity

This is the part a new library must get right, because it opens a **second**
operating-system resource for a PID that `memdiver` already pinned.

**`RemoteCaller::open(pid)` — preferred:**

1. Windows: `OpenProcess` with `PROCESS_CREATE_THREAD`,
   `PROCESS_QUERY_INFORMATION`, `PROCESS_VM_OPERATION`, `PROCESS_VM_READ`,
   `PROCESS_VM_WRITE`, and `PROCESS_SYNCHRONIZE`. The handle pins the process
   object.
2. Linux: `PTRACE_SEIZE` + `PTRACE_INTERRUPT` the main TID and wait for the
   stop. The traced task cannot be reaped/reused while the trace is active.
3. `memdiver::Process::open(pid)`.
4. Check `process.is_alive()` again. On Linux, detach and fail if it is false;
   on success, detach before returning so the target is not left stopped. A
   failed detach is itself an error, not a silent success.

Because the execution resource was acquired first, the PID could not have been
recycled between the two opens. On Windows the kernel object stays pinned for
the lifetime of the `RemoteCaller`; on Linux the construction-time trace only
needs to cover the `Process::open` handshake, after which the `memdiver` handle
pins the instance for the double-liveness check on every call.

**`RemoteCaller::new(process)` — adopt an existing handle:**

1. Reject `!process.is_writable()` before any OS call.
2. Check `process.is_alive()`. If false, fail with `TargetExited`.
3. Open the execution resource by `process.pid()`. On Linux this is a short
   attach/verify/detach handshake, not a persistent stop.
4. Check `process.is_alive()` again. If false, close/detach the execution
   resource and fail with `TargetExited`.

The second check is the safety argument. A pinned `memdiver::Process` is alive
only while *its* instance is running. If the PID had been recycled between
steps 2 and 3, the old instance exited, so step 4 would observe
`is_alive() == false`; the library discards the execution resource. If step 4
is true, the old instance never exited during the window, so the PID still
referred to it when the execution resource was opened. Once bound, the
execution resource cannot switch instances: a Windows `HANDLE` pins the process
object, and a Linux ptrace attachment pins the task while it is attached.
Because Linux detaches between calls, the same double check is repeated on
every call (see below).

Both pin orderings are exercised by the on-top prototypes; the exact
`RemoteCaller::new` API and its error paths still need an integration test that
opens `memdiver`, wraps it, and calls successfully.

**Linux per-call attach:** `RemoteCaller` does not keep the target stopped
between calls. Each `call` does:

1. `process.is_alive()`.
2. attach/interrupt the TID.
3. `process.is_alive()` again; if false, detach and return `TargetExited`.
4. run the call, restore state, detach.

This gives the same double-liveness protection on every call and leaves the
target running between calls. The trace itself is the pin for the duration of
the call.

### 3.5 Errors and cleanup

Use a new error type; do not extend `memdiver::Error`.

```rust
#[non_exhaustive]
pub enum Error {
    /// Opening the execution resource or the memory handle failed.
    Open { pid: u32, source: Box<dyn std::error::Error + Send + Sync> },
    /// The handle was opened read-only.
    ReadOnly,
    /// The target exited or its PID was reused.
    TargetExited { pid: u32 },
    /// The platform cannot perform this call.
    Unsupported { operation: &'static str, reason: &'static str },
    /// The function address is not executable, or an argument is invalid.
    InvalidAddress { address: Address, reason: &'static str },
    InvalidArgument { index: usize, reason: &'static str },
    /// The platform call failed; keeps the raw OS code.
    Platform { operation: &'static str, source: PlatformError },
    /// The call ran but did not produce a normal integer result.
    CallFailed { function: Address, status: CallStatus },
    /// Restoring/detaching failed. `call` is `Some` if the call also failed.
    Cleanup {
        function: Address,
        call: Option<Box<Error>>,
        cleanup: Box<Error>,
    },
}

#[non_exhaustive]
pub enum CallStatus {
    /// The remote thread returned a non-zero exit code.
    ThreadExit(u32),
    /// The tracee stopped with an unexpected signal.
    Signal(i32),
    /// The target exited while the call was in flight.
    Exited,
}
```

Cleanup must be attempted on every path, and a cleanup failure must not mask the
call failure. This mirrors `Process::write_code`'s composite-error discipline:
keep both failures and distinguish “call failed, cleanup succeeded” from
“cleanup failed”. On Linux a guard restores GP/FP/debug state and detaches even
if setup fails; on Windows a guard closes thread/allocation handles and frees
the stub/result only after the thread has exited.

### 3.6 Threading and `Drop`

`Process` is `Send + Sync`; `RemoteCaller` should be too. Calls on one
`RemoteCaller` must be serialized with an internal mutex: two Linux calls on
one target thread would corrupt each other, and two Windows calls would race on
the same process even though their allocations are independent. Two separate
`RemoteCaller`s for the same target are not coordinated; a concurrent Linux
attach fails with `EBUSY` and must be reported, not retried.

On Linux, `RemoteCaller` holds no trace between calls, so `Drop` has nothing to
detach. The per-call `TraceGuard` handles the active call. If the library
process is killed with `SIGKILL` during a call, the target can remain stopped;
`PTRACE_O_EXITKILL` would kill the target instead, which is usually worse.
Document the operational consequence.

On Windows, `Drop` closes the execution handle. A call cannot be in progress
while `Drop` runs because `call` borrows `&self`; if the caller shares the
`RemoteCaller` through `Arc`, the last reference cannot be dropped while a call
holds a borrow.

---

## 4. Windows mechanism

### 4.1 `x86_64`: `CreateRemoteThread` plus a generated stub

`CreateRemoteThread` requires `PROCESS_CREATE_THREAD`,
`PROCESS_QUERY_INFORMATION`, `PROCESS_VM_OPERATION`, `PROCESS_VM_READ`, and
`PROCESS_VM_WRITE` ([Microsoft docs][createthread]). The started routine is
called as `LPTHREAD_START_ROUTINE` and its exit code is only a 32-bit `DWORD`,
so the actual return value is stored in remote memory.

The stub (validated under Wine):

1. `sub rsp, 0x38` — 32-byte shadow space, two stack argument slots, and
   16-byte alignment;
2. load `RCX`, `RDX`, `R8`, `R9` with arguments 1–4;
3. store arguments 5–6 at `[rsp+0x20]` and `[rsp+0x28]`;
4. `mov rax, function; call rax`;
5. `mov [result], rax` — the absolute result address is patched into the stub;
6. `xor eax, eax; add rsp, 0x38; ret` — thread exit code zero.

The stub is allocated `PAGE_READWRITE`, written through `memdiver`, changed to
`PAGE_EXECUTE_READ`, and flushed with `FlushInstructionCache`. The result slot
must live in a **separate writable allocation**: `VirtualProtectEx` works on
whole pages, so putting the result immediately after the stub would make it
read-only too. The prototype initially did that and the remote thread faulted on
the result store; two allocations fixed it.

### 4.2 `x86`

On 32-bit Windows all arguments are on the stack. The stub pushes them
right-to-left, loads the function into `EAX`, calls it, adjusts `ESP` for
`cdecl` (not for `stdcall`/`thiscall`, which clean up themselves), stores
`EAX` (and `EDX` for a 64-bit return), and returns with `ret 4` because the
thread start routine itself is `stdcall`.

The calling convention matters:

* `cdecl`: caller cleans all arguments.
* `stdcall`: callee cleans; `ret N`.
* `thiscall`: `this` in `ECX`, rest on the stack; usually callee cleans.
* `fastcall`: first two arguments in `ECX`/`EDX`, rest on the stack; callee
  cleans.
* A 64-bit argument occupies two 32-bit stack slots (low word first), not one
  64-bit slot.
* Addresses above `u32::MAX` cannot be represented in a 32-bit target; reject
  them rather than truncate.

A C prototype in `target/rc-win32` validated `cdecl` with two and six
arguments under Wine. The Rust `i686-pc-windows-gnu` target was not installed
locally, so the Rust path needs a CI target and a Rust implementation test.

### 4.3 W^X, CFG, CET, and unwinding

* **W^X:** never leave an RWX page. Allocate RW, write, protect RX, flush. The
  result slot stays RW in a separate page.
* **CFG:** an indirect `call rax` is subject to Control Flow Guard. A direct
  `call rel32` is not. Prefer allocating the stub within ±2 GiB of the function
  and generating a direct call; if the allocation cannot be placed in range,
  fall back to an indirect call and accept that CFG may reject a non-CFG target.
  Native Windows testing is required; Wine does not enforce CFG.
* **CET shadow stack:** the stub uses a real `call`, so the callee's `ret`
  matches the shadow-stack entry. The thread start entry is created by the OS;
  native CET testing is still needed.
* **CET IBT:** a direct call avoids the indirect-branch check. An indirect call
  may require `ENDBR64` at the target on IBT-enabled systems.
* **Unwinding:** the generated stub has no `.pdata`/unwind info. C++
  exceptions that unwind through the stub are unsupported and can terminate the
  target. Document this; do not attempt to generate unwind metadata in v1.
* **Thread creation side effects:** DLL thread-attach notifications, loader lock
  interactions, a new thread in the target's thread list, changed timing and
  memory layout. All are observable.

### 4.4 Handle rights and failures

`memdiver::Process::open` does **not** request `PROCESS_CREATE_THREAD`; the new
library's own `OpenProcess` does. This is a feature of the separate-crate
design: `memdiver`'s existing users do not pay for a right they do not need,
and the remote-call library can return a precise “execution handle denied”
error.

If `CreateRemoteThread` is called with an invalid start address, the OS may
terminate the new thread with an error exit rather than fail the call. Validate
the function address against an executable live region with
`Process::region_at` before creating the thread; that is a best-effort check,
not a guarantee that the function signature is correct.

If the remote thread hangs, `WaitForSingleObject(INFINITE)` hangs the caller.
Closing the thread handle does not stop the thread; `TerminateThread` can leave
locks held and the CRT/heap inconsistent. v1 does not offer cancellation.

---

## 5. Linux mechanism

### 5.1 Attach and identity

`ptrace` is per-thread; the `pid` argument is a TID. v1 attaches the main
thread (`TID == PID`) with `PTRACE_SEIZE` + `PTRACE_INTERRUPT`, then waits for
the `PTRACE_EVENT_STOP`. `PTRACE_SEIZE` does not stop the tracee by itself;
`PTRACE_INTERRUPT` does ([ptrace(2)][ptrace]). Older kernels without `SEIZE`
can fall back to `PTRACE_ATTACH` later; v1 can require `SEIZE`. If the
thread-group leader has exited while other threads remain, `PTRACE_SEIZE(PID)`
fails; v1 reports that and does not silently pick another thread.

The attach happens **before** `memdiver::Process::open`, so the traced task pins
the instance while the memory handle is opened. The prototype's
`Process::open` while traced, `region_at`, and `write` all succeeded.

If the target is already being traced by a debugger, `PTRACE_SEIZE` fails with
`EPERM`/`EBUSY`; report it and do not fight the existing tracer. Yama
`ptrace_scope`, `PR_SET_PTRACER`, `CAP_SYS_PTRACE`, seccomp, user namespaces,
and container capabilities all apply, just as they do for `/proc/<pid>/mem`.

### 5.2 Hardware breakpoint instead of `int3`

An `int3` design writes `0xCC` over the interrupted instruction and restores it
after the trap. It works (the `target/rc-poc` prototype validates it), but it
has two problems:

1. it writes to target code, which is unsafe for a shared/file-backed mapping;
2. it requires a code restore on every failure path, and a crash before the
   restore leaves the target patched.

A **hardware execution breakpoint** avoids both. On x86/x86_64:

1. Save `DR0`–`DR7` with `PTRACE_PEEKUSER` at
   `offset_of!(libc::user, u_debugreg)`.
2. Find a free slot among `DR0`–`DR3` (both L and G bits clear in `DR7`).
3. Set `DRi = interrupted RIP`; in `DR7`, clear the slot's L/G and RW/LEN
   fields and set the local-enable bit (RW=00, LEN=00 for execute).
4. Redirect `RIP` to the function and `RSP` to the call frame.
5. Resume. When the callee returns to the interrupted instruction, the
   breakpoint fires before that instruction executes.
6. Read `RAX`, then restore the debug registers and the saved GP state.

Validated on Linux 7.3: two and eight arguments, a busy-spinning target, a
target blocked in `read(2)`, and two consecutive calls. The target resumed and
its `read` completed after detach.

Two non-obvious details:

* **Acknowledge `DR6` first.** On the test kernel, `PTRACE_POKEUSER(DR7)`
  returned `EIO` while the slot's breakpoint-hit status bit in `DR6` (B0–B3)
  was still set. Writing `DR6 = 0` before restoring `DR7`/`DRi`, then restoring
  the saved `DR6`, made the restore succeed. This is a concrete example of why
  the Linux backend needs adversarial tests.
* **Do not clobber a debug register the target uses.** Save all eight, choose a
  free slot, restore exactly. If no slot is free, return a clear error; an
  `int3` fallback would need the shared-mapping check that the hardware design
  avoids.

Hardware breakpoints are per-thread and visible to the target; they are not a
stealth feature. A target that uses all four debug registers cannot be called
with this mechanism in v1.

### 5.3 Call frame and red zone

The SysV AMD64 ABI has a 128-byte red zone below `RSP` that a leaf function may
use. The first prototypes wrote the return address at `RSP - 8`, which is inside
the red zone; that is a bug for production. The corrected frame:

```text
saved.rsp
    ... live red zone, must not be touched ...
saved.rsp - 128
    [stack arguments 7..]      <- highest address of the frame
    [return address]           <- frame top, rsp % 16 == 8
    ... callee stack grows down ...
```

Compute:

```text
stack_args  = 8 * max(0, args.len() - 6)
limit       = saved.rsp - 128 - stack_args
frame       = ((limit - 8) & !0xF) - 8
```

so `frame + 8 + stack_args <= saved.rsp - 128` and `frame % 16 == 8` at the
callee's entry. Every subtraction must be checked; a stack pointer near the
bottom of the address space is a clean error, not a panic. Verify with
`Process::region_at` that the whole frame range is writable and that the stack
region has headroom below it (the prototype requires 4 KiB). That headroom is a guard
band, not a proof that the callee's full stack usage fits: a deeply recursive
function can still reach the guard page. Write the return address and stack
arguments in one `Process::write` call.

`rflags` should be sanitized for a function call: clear the direction flag
(`DF`) and trap flag (`TF`) at minimum; the ABI requires `DF = 0` at function
entry. The saved flags are restored after the call.

### 5.4 Full thread state

A function call clobbers caller-saved registers, flags, and FP/SIMD state. The
interrupted thread may be inside libc or a JIT with live values in those
registers. Save and restore:

* GP registers, `rflags`, `fs_base`, `gs_base` (`PTRACE_GETREGS` /
  `user_regs_struct` covers these on x86_64);
* FP/SIMD state (`PTRACE_GETREGSET` with `NT_X86_XSTATE` where supported,
  `NT_FPREGSET`/`PTRACE_GETFPREGS` fallback; AVX/AVX-512 state needs XSTATE);
* debug registers `DR0`–`DR7`;
* `orig_rax`, the syscall-restart state.

The prototype saves GP registers and debug registers, but not FP/XSTATE; the
production version must.

### 5.5 Syscall restart and signals

If the thread was blocked in a syscall when interrupted, the kernel may restart
that syscall when the tracee is resumed. Without intervention the redirect can
land in the wrong place. Setting `orig_rax = -1` (`u64::MAX`) before resuming
cancels the restart. Restoring the full register state before detaching lets
the interrupted `read(2)` complete normally afterwards. This was reproduced:
the blocked-in-`read` prototype failed until `orig_rax` was invalidated, then
returned the correct result and the target's `read` completed.

Signal policy needs a deliberate choice:

* a `SIGTRAP` at `RIP == breakpoint` with `si_code == TRAP_HWBKPT` and the
  expected `DR6` bit is the call return;
* other signals can be forwarded with `PTRACE_CONT(signal)` and the wait loop
  continues;
* a fault inside the called function (bad pointer, stack overflow, illegal
  instruction) may kill the target; return a `CallFailed` with the wait status
  rather than pretending the call succeeded;
* swallowing a fatal signal changes target semantics; forwarding it while the
  fake frame is on the stack can mislead handlers. v1 should forward
  non-breakpoint signals and report the call as failed if the target dies.

C++ exceptions and `longjmp` that unwind through the fake frame are unsupported:
the unwinder sees a return address at the interrupted PC with no call-site
metadata.

### 5.6 CET shadow stack

The fake-return technique does **not** execute a `call`; it only writes the
return address to the normal stack. With CET shadow stack (SHSTK) enabled, the
callee's `ret` compares the normal and shadow stacks and faults. A Linux
implementation must detect SHSTK for the target (for example from
`/proc/<pid>/status`'s `x86_Thread_features`/`x86_Thread_features_locked`
fields, or the CET XSTATE components) and either refuse with
`Error::Unsupported` or switch to an executable trampoline that performs a real
`call`. Do not assume CET is absent on a modern Linux target.

The hardware breakpoint still helps here: it removes the code write, but it
does not create a shadow-stack entry. v1 should refuse when SHSTK is detected.

### 5.7 Alternatives considered

| Mechanism | New thread | Existing thread | Why not v1 |
|---|---|---|---|
| `ptrace` + `int3` at interrupted RIP | no | yes | writes target code; shared mappings; restore on every path |
| `ptrace` + hardware breakpoint | no | yes | chosen; v1 x86/x86_64 |
| remote `clone`/`pthread_create` call | yes | bootstrap | TLS, stack, libc internals; a second design |
| signal-handler injection | no | yes | needs a pre-existing handler and known signature |
| `/proc/<pid>/mem` + `write_code` hook | no | target event | not a call; requires a trigger and a code cave |
| `process_vm_readv`/`writev` | no | no | memory only; cannot change RIP |

---

## 6. Prototype results

### 6.1 Environment

Linux `x86_64` 7.3, Yama `ptrace_scope=1`; Wine 11.21;
`x86_64-w64-mingw32-gcc` and `i686-w64-mingw32-gcc`. The Rust
`i686-pc-windows-gnu` target was not installed, so the 32-bit path is a C
prototype only.

### 6.2 Earlier mechanism prototypes

* `target/rc-poc` (Linux x86_64, `int3`): 2- and 6-argument `extern "C"`
  functions, busy-spinning and blocked-in-`read` targets, repeated calls,
  restore/detach. The blocked case failed until `orig_rax` was invalidated;
  with the fix (`POC_BLOCK=1 POC_CANCEL_SYSCALL=1`) it returns the correct
  value and the target's `read` completes.
* `target/rc-win` (Windows x86_64, Wine): `OpenProcess` with
  `PROCESS_CREATE_THREAD`, `VirtualAllocEx` + `WriteProcessMemory` for a
  generated stub, `CreateRemoteThread`, 2- and 6-argument functions, 64-bit
  result from remote memory, thread exit code zero.
* `target/rc-win32` (Windows x86, Wine, C): `cdecl` stub, stack arguments,
  `ret 4`, 32-bit result.

### 6.3 On-top Linux prototype (`target/rc-on-top`, memdiver public API)

Sequence:

1. spawn child, read `READY` with function addresses;
2. `PTRACE_SEIZE` + `PTRACE_INTERRUPT` the main thread;
3. `Process::open(pid)` through memdiver while the task is traced;
4. `pointer_width()`, `region_at(rsp)`, `region_at(function)`;
5. hardware breakpoint; frame written through `Process::write`;
6. call, read `RAX`, restore registers and debug registers;
7. `PTRACE_DETACH`; send `PING` / a stdin line.

Validated:

* `poc_add` with two 64-bit arguments and `poc_mix` with six;
* `poc_eight` with eight arguments using the red-zone-safe frame (562);
* a busy-spinning target and a target blocked in `read(2)`;
* the target answered `AFTER hello` after detach in the blocked case;
* two consecutive calls on the same stopped thread, each starting from the
  saved state;
* the `memdiver`-first ordering (the `RemoteCaller::new` shape) with
  `is_alive()` checks on both sides of the attach.

This is the strongest evidence that the library can be built **only** on
`memdiver`'s public API: all memory reads/writes and region queries went
through `memdiver`; only the ptrace/register mechanism was local to the
prototype.

### 6.4 On-top Windows prototype (`target/rc-on-top`, Wine)

Sequence:

1. spawn child, read `READY`;
2. `OpenProcess` with the execution rights (pins the process);
3. `Process::open(pid)` through memdiver while the execution handle is open;
4. `VirtualAllocEx` for the stub page and a separate result page;
5. write the stub through `Process::write`;
6. `VirtualProtectEx` the stub to `PAGE_EXECUTE_READ` + `FlushInstructionCache`;
7. `CreateRemoteThread`, `WaitForSingleObject`, `GetExitCodeThread`;
8. read the result through `Process::read_value`;
9. free both allocations.

Validated under Wine: 2- and 6-argument functions, 64-bit result, thread exit
code zero, and both pin orderings (execution-first and `memdiver`-first with
liveness checks). The first attempt put the result immediately after the stub;
after the stub page was made RX, the remote thread faulted on the result store.
Separate allocations fixed it. This is a W^X design detail worth keeping in the
implementation notes.

### 6.5 What the prototypes do not settle

* native Windows (CFG, CET, EDR/anti-cheat, WOW64);
* Linux signals/faults inside the called function, FP/XSTATE restoration, and
  CET shadow stack;
* multi-threaded targets and thread selection;
* 32-bit Rust targets and `thiscall`/`fastcall`;
* timeouts, cancellation, and a hung call;
* general remote allocation and string/struct arguments;
* the exact `RemoteCaller::new` API and its error paths (the underlying
  `memdiver`-first ordering and liveness checks were validated, but not the
  proposed API).

### 6.6 Reproduction

The scratch crate is outside the workspace and is not part of the quality gate.
From the repository root:

```sh
cargo run --manifest-path target/rc-on-top/Cargo.toml --bin linux
POC_BLOCK=1 cargo run --manifest-path target/rc-on-top/Cargo.toml --bin linux

cargo build --manifest-path target/rc-on-top/Cargo.toml \
  --target x86_64-pc-windows-gnu --bin windows
WINEDEBUG=-all wine target/rc-on-top/target/x86_64-pc-windows-gnu/debug/windows.exe
```

The Linux runs need ptrace permission for the child (the normal descendant
case). Set `POC_MEMDIVER_FIRST=1` to exercise the `memdiver`-first ordering.
The `int3` and Windows mechanism prototypes under `target/rc-poc`,
`target/rc-win`, and `target/rc-win32` can be run the same way.

---

## 7. Hard problems and decisions

### 7.1 Timeout and cancellation

There is no safe way to abort a function call in another process.

* **Windows:** if `WaitForSingleObject` times out, the new thread is still
  running inside the target. `TerminateThread` can leave locks held and the
  CRT/heap inconsistent. Freeing the stub while the thread runs is a
  use-after-free. Closing the thread handle only loses the ability to observe
  it.
* **Linux:** if the call does not return, the target thread is running inside
  the called function with a fake frame, and the caller is blocked in
  `waitpid`. Detaching would resume a half-executed call with clobbered
  caller-saved state; interrupting and leaving it stopped freezes one target
  thread. Killing the target is not an acceptable library action.

Options:

1. **No timeout in v1.** The call blocks until the function returns, the thread
   exits, or the process exits. Honest and uniform; a hung call hangs the
   caller.
2. **A `RemoteCall` handle.** Return before completion and let the caller wait
   with a timeout; on timeout the call is abandoned. Windows leaks the remote
   thread/allocations; Linux leaves the tracee stopped or needs a target-created
   thread that can be abandoned. More API, more failure modes.
3. **`TerminateThread`/kill the target.** Reject as a library default.

Recommendation: option 1 for v1. Add option 2 only after the asynchronous
design exists, and do not expose a timeout that silently leaks target
resources.

### 7.2 Thread affinity and deadlocks

A new Windows thread is not the target's main thread. Functions that assume the
main thread, a specific thread-local, or a lock held by the caller can misbehave
or deadlock. A hijacked Linux thread has the opposite problem: it may be
holding a lock that the called function needs.

There is no general solution. v1 uses the Linux main thread and a fresh Windows
thread; document the hazard, offer thread selection later, and do not pretend
the call is transparent.

### 7.3 ABI diversity

`x86_64` has one integer calling convention per platform, which keeps v1
tractable. `x86` does not: `cdecl`, `stdcall`, `thiscall`, `fastcall`, `EDX:EAX`
returns, multi-slot 64-bit arguments, floating-point and struct returns.
v1 supports integer/pointer arguments and returns only, and returns
`Unsupported` for SIMD/struct/vararg signatures rather than guessing.

### 7.4 Target side effects

A remote call can run DLL thread-attach notifications, change the target's
thread count and timing, allocate/free, take locks, mutate globals, send network
traffic, or crash. On Linux it leaves a `TracerPid` entry while attached and can
cause `EINTR` in the interrupted thread's syscalls. On Windows it creates
observable thread-creation telemetry. Document all of this; the caller owns the
consequences.

### 7.5 Security and ethics

Remote calls are dual-use. They are legitimate for debugging, modding with
consent, automation of software you own, and research. They are also a standard
malware primitive. The library should:

* require authorization language in the docs, as `memdiver` already does for
  memory writes;
* keep the OS permission model as the only access boundary.

This is consistent with `memdiver`'s README and should remain a non-goal.

---

## 8. Testing strategy

The existing fixture (`crates/memdiver-integration-tests/src/bin/memdiver-fixture.rs`)
is the right target. It blocks on stdin, so the parent can trace/redirect its
main thread and then verify it still answers `PING`.

Fixture functions to add:

| Function | Purpose |
|---|---|
| `call_add(a, b) -> u64` | two register arguments, 64-bit return |
| `call_mix(a..f) -> u64` | six arguments (register + stack on x64) |
| `call_eight(a..h) -> u64` | stack arguments and red-zone-safe frame (prototype; v1 caps at six) |
| `call_store(ptr, value)` | pointer argument; target writes a known value |
| `call_ping() -> u64` | zero arguments |
| `call_stdcall` / `call_thiscall` (x86) | calling conventions |
| `call_exit()` | target exits during the call, controlled test |

Do not add a function that intentionally crashes or calls a mismatched ABI; that
cannot assert a library error without making the fixture disposable.

Tests:

* call each fixture function and assert the result;
* after every call, send `PING` and assert `PONG` (the interrupted thread
  resumed; the target survived);
* pointer argument + read back the target-written value through `memdiver`;
* read-only handle returns the library's `ReadOnly` error before any OS call;
* target exit during a call returns `TargetExited`/`CallFailed`, not a hang;
* unsupported ABI/architecture returns `Unsupported`;
* Linux: call while the fixture is blocked in `read(2)` (the `orig_rax`
  regression);
* Linux: two consecutive calls, and (prototype/phase 2) a call with eight
  arguments;
* Windows: x64 under Wine locally and native Windows in CI;
* Windows: x86 if the target is supported;
* unit tests for the stub builder (exact bytes, stack layout, alignment,
  argument count limits), the Linux frame math (red zone, alignment, stack
  arguments), debug-register slot selection/DR7 bits, and the composite
  cleanup error;
* no test that intentionally calls a bad address or mismatched ABI.

The remote-call integration tests can live in the existing
`memdiver-integration-tests` crate with a dev-dependency on `memdiver-call`,
which keeps one fixture and one harness. If the library is maintained in a
separate repository, give it its own fixture and harness instead.

CI:

* Linux tests need ptrace permission for a descendant process; if the CI
  sandbox blocks the `ptrace` syscall, the job needs the capability or a
  documented reason. Do not mark tests `#[ignore]` to hide that.
* Windows native CI must cover x64; add `i686-pc-windows-gnu` to the cross-check
  matrix if x86 is supported.
* Cross-check the new crates for `x86_64-pc-windows-gnu` even when the host is
  Linux.

---

## 9. Phases and effort

| Phase | Scope | Why |
|---|---|---|
| 0 | API/error design, fixture functions, crate skeleton | lock semantics before code |
| 1 | Windows x64 same-bitness, integer args/return, synchronous | lowest-risk platform; proves the API |
| 2 | Linux x64 same-bitness, hardware breakpoint, GP + FP state, sync | parity; hardest failure paths |
| 3 | Windows x86 conventions, `i686` CI target | the 32-bit use case |
| 4 | `call_export`, string/struct argument buffers, allocation | practical APIs |
| 5 | Thread selection, async/timeout, CET trampoline, ARM64 | separate designs |

The first milestone should be a `memdiver-call` 0.1 with `RemoteCaller::open`,
`RemoteCaller::new`, `call`, `call_export`, Windows x64 and Linux x64 support,
fixture-backed tests, and explicit `Unsupported` errors for everything outside
that matrix. Do not publish a timeout, x86, or ARM64 claim until the
corresponding phase has its own tests.

Rough effort for a production-grade first release:

| Work | Estimate |
|---|---|
| API/error design, fixture, docs | 2–3 days |
| Windows x64 mechanism + stub + tests | 3–5 days |
| Linux x64 ptrace/hardware breakpoint + state + tests | 5–8 days |
| Windows x86 conventions + CI target | 3–5 days |
| Integration tests, native Windows/Wine validation | 3–5 days |
| Review, docs, cross-check | 2–4 days |
| **Total (v1: Win x64 + Linux x64)** | **roughly 3–4 weeks** |
| **Total with Windows x86** | **roughly 4–6 weeks** |

The estimate is dominated by failure-path testing and platform verification,
not by the happy-path call. The prototypes took hours; making them safe is the
work.

---

## 10. Decision

The feature is feasible, and it can be built without changing `memdiver`. The
remaining decisions are product decisions:

1. **Separate library or in-tree?** Recommend a separate `memdiver-call` crate
   (same repository is fine). It preserves `memdiver`'s guarantee and release
   cadence.
2. **Is Windows x86 required for v1?** If yes, the `i686` build/CI target and
   the convention matrix are part of the feature, not an optional extra.
3. **Is Linux parity required?** If not, a Windows-only v1 with
   `Error::Unsupported` on Linux is allowed by the existing parity rules, but
   it is a visible product asymmetry.
4. **Is a synchronous, non-cancellable call acceptable?** If not, design the
   async/timeout semantics first; they are much harder than the call itself.
5. **Is native Windows (CFG/CET/WOW64) test infrastructure available?** Wine
   proves the basic mechanism but not the mitigations.
6. **Is the library allowed to attach/trace and create remote threads?** The
   README guarantee must remain true for `memdiver`; the new crate must say what
   it does.

If the answer to (1) is “in-tree”, the narrow v1 above is still the lowest-risk
path, but the handle-rights change, error enum, and README guarantee need a
deliberate design. If remote calls are out of scope for the product, do not add
them: the existing read/write/scan API is coherent and the guarantee is
valuable.

---

## References

* Microsoft, [`CreateRemoteThread`][createthread]
* Microsoft, [`GetExitCodeThread`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodethread)
* Microsoft, [`VirtualAllocEx`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
* Microsoft, [Control Flow Guard](https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard)
* Microsoft, [WOW64 implementation details](https://learn.microsoft.com/en-us/windows/win32/winprog64/wow64-implementation-details)
* Raymond Chen, [“Is there a problem with `CreateRemoteThread` on 64-bit systems?”](https://devblogs.microsoft.com/oldnewthing/20180615-00/?p=99025)
  — why copying a compiled function into the target is not a valid stub
  strategy; generate known bytes instead.
* Linux, [`ptrace(2)`][ptrace] — per-thread tracing, `PTRACE_SEIZE`/`INTERRUPT`,
  syscall stops, access checks, `PTRACE_PEEKUSER`/`POKEUSER`.
* Linux, [Yama LSM](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
  — `ptrace_scope`.
* Linux, [`prctl(2)`](https://man7.org/linux/man-pages/man2/prctl.2.html) —
  `PR_SET_PTRACER` and `PR_SET_DUMPABLE`.
* GDB, [`gdb/infcall.c`](https://sourceware.org/git/?p=binutils-gdb.git;a=blob_plain;f=gdb/infcall.c;hb=HEAD)
  — the reference implementation of inferior function calls, including dummy
  frames and return breakpoints.
* Microsoft, [`QueueUserAPC`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
* Microsoft, [`SuspendThread`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread),
  [`GetThreadContext`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext),
  [`SetThreadContext`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext)

[createthread]: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
[ptrace]: https://man7.org/linux/man-pages/man2/ptrace.2.html
