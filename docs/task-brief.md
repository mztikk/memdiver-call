# Task brief: build `memdiver-call`, an independent remote-call library

> **How to use this file:** give the whole file to the implementing agent as
> its task prompt. It is self-contained. The agent must read the entire brief
> before writing code, work autonomously, create its own repository/workspace,
> and report back with the evidence listed at the end.

**Working name:** `memdiver-call` (safe crate) with `memdiver-call-sys`
(platform crate). If either name is unavailable on crates.io, choose a close
alternative and note it in the README and final report.

---

## 1. Mission

Build a production-quality Rust library that calls functions inside another
local process. The library **consumes `memdiver` as an ordinary dependency** and
is an entirely separate project:

* it must not be a member of the `memdiver` Cargo workspace;
* it must not modify, fork, vendor, or patch `memdiver`;
* it must not depend on `memdiver-core` or `memdiver-sys` internals;
* it must depend only on the public `memdiver` façade
  (`Process`, `Address`, `Error`, `Module`, `Export`, ...).

The library is allowed to be invasive: it attaches a tracer on Linux and creates
a remote thread on Windows. It must document that clearly.

A detailed investigation of this problem exists in the `memdiver` repository at
`docs/remote-call-investigation.md`. Read it if it is available; it contains
prototype results and pitfalls. **This brief is authoritative for what to
build.** If the investigation and this brief disagree, this brief wins.

## 2. Hard constraints

1. **Independence.** Own Git repository or standalone Cargo workspace. Depend on
   `memdiver = "0.2"` from crates.io (a temporary path dependency is acceptable
   for local development, but do not commit a workspace coupling).
2. **No `memdiver` changes.** If the public API appears insufficient, stop and
   report the gap. Do not reach into private modules, do not call
   `memdiver-sys`, and do not copy `memdiver` source into the new project.
3. **Safe/unsafe split.** The safe crate must use `#![forbid(unsafe_code)]`.
   All FFI and platform code lives in `memdiver-call-sys`. Every `unsafe` block
   needs a `// SAFETY:` comment naming its invariant. Every public `unsafe fn`
   or `unsafe trait` needs a `# Safety` section.
4. **No panics on untrusted input.** Bad addresses, bad TIDs, arithmetic
   underflow/overflow, malformed `/proc` data, and OS failures return errors.
   Panics are reserved for impossible internal invariants and documented API
   contract violations.
5. **No silent truncation.** A write/read is success only if the full requested
   range transferred. `memdiver` already enforces this for its own operations;
   do not bypass it with raw syscalls for target memory I/O.
6. **No RWX.** On Windows the stub page is RW while written, then RX. The result
   page stays RW in a separate allocation.
7. **Cleanup on every path.** Restore target state, detach, close handles, and
   free remote allocations. A cleanup failure must not mask a call failure; keep
   both in a composite error.
8. **MSRV 1.85, edition 2024**, stable Rust. Do not use library features newer
   than the MSRV.
9. **No publishing.** Commit locally and report; do not publish to crates.io
    without explicit approval.
10. **Stop rather than silently weaken.** If a hard constraint cannot be met
    (for example, the public API is insufficient or a required platform cannot
    be tested), stop and report the concrete blocker. Do not replace it with an
    unsafe shortcut or an undocumented limitation.

## 3. Deliverables and repository layout

Create a standalone workspace:

```text
memdiver-call/                  # safe API crate, publishable
    src/lib.rs                  # #![forbid(unsafe_code)]
    src/error.rs
    src/options.rs
    src/caller.rs
    README.md
    CHANGELOG.md
    LICENSE-MIT
    LICENSE-APACHE
memdiver-call-sys/              # unsafe platform mechanism, publishable
    src/lib.rs
    src/linux.rs
    src/windows.rs
memdiver-call-tests/            # publish = false
    src/bin/memdiver-call-fixture.rs
    tests/remote_call.rs
    tests/common/mod.rs
Cargo.toml                      # workspace, resolver = "3"
rust-toolchain.toml             # stable, matching MSRV policy
```

`memdiver-call-tests` depends on `memdiver-call` and `memdiver`. Its fixture
binary is the child process used by the end-to-end tests. Keeping the fixture
and its integration tests in the same package makes
`env!("CARGO_BIN_EXE_memdiver-call-fixture")` work; do not rely on a
cross-package binary path.

Use `libc` on Linux and `windows-sys` (or direct `extern "system"` bindings) on
Windows. Prefer `windows-sys` if it keeps the unsafe surface smaller and the
code clearer. Use the same dual MIT/Apache-2.0 licensing as `memdiver`.

## 4. Version 1 scope

Required:

* Windows `x86_64` → `x86_64`;
* Linux `x86_64` → `x86_64`;
* same-bitness only;
* integer and pointer arguments (`u64` slots), up to **six** arguments;
* integer/pointer return values (`u64`);
* one synchronous call that runs to completion;
* a writable `memdiver::Process`;
* `RemoteCaller::open(pid)`, `RemoteCaller::new(Process)`, `call`, and
  `call_export`;
* explicit `Unsupported` for everything outside the matrix.

Explicitly out of scope for the required v1 matrix (return `Unsupported`, or
omit the API):

* WOW64 and cross-bitness calls;
* Linux 32-bit targets and 32-bit hosts;
* ARM64 and other architectures;
* timeouts, cancellation, async calls, and thread hijacking;
* floating-point, SIMD, struct-by-value, variadic, and C++ `thiscall`-on-x86
  argument support;
* general remote allocation and string/struct argument buffers;
* thread selection on Linux (use the main thread).

Windows `x86` native is an optional stretch goal, not part of the required x64
matrix. If the `i686-pc-windows-gnu` target is available and all Windows x86
tests can be run, you may add x86 `cdecl`/`stdcall`, but do not claim it without
tests. Do not add `thiscall`/`fastcall` unless you can test them.

If the intended deployment target is a 32-bit Windows process, Windows `x86`
is **not optional**: promote it to required, add the `i686-pc-windows-gnu`
target/CI job, and do not call the task complete with only x64.

## 5. Public API

The exact shape is yours to refine, but keep it small and explicit. The
following is the required capability and naming direction:

```rust
use memdiver::{Address, Process};

#[non_exhaustive]
pub enum CallAbi {
    Auto,
    Cdecl,
    Stdcall,
    Thiscall,
    Fastcall,
}

#[non_exhaustive]
pub struct CallOptions { /* private fields */ }

impl CallOptions {
    pub fn new() -> Self;
    pub fn with_abi(self, abi: CallAbi) -> Self;
    pub fn with_thread(self, tid: u32) -> Self; // Linux-only in v1
}

pub struct RemoteCaller { /* private */ }

impl RemoteCaller {
    pub fn open(pid: u32) -> Result<Self, Error>;
    pub fn new(process: Process) -> Result<Self, Error>;
    pub fn process(&self) -> &Process;
    pub fn call(&self, function: Address, args: &[u64], options: &CallOptions) -> Result<u64, Error>;
    pub fn call_export(&self, module: &str, export: &str, args: &[u64], options: &CallOptions) -> Result<u64, Error>;
}
```

Requirements:

* `CallAbi::Auto` is Microsoft x64 on Windows x64 and SysV AMD64 on Linux x64.
  On x64, every other variant returns `Unsupported`.
* The required v1 matrix uses `x86_64` hosts. On any other host architecture,
  return `Unsupported` (or fail to compile with a clear message) unless you
  have implemented and tested that architecture, such as the optional Windows
  `x86` stretch goal.
* `with_thread` is Linux-only and optional in v1. If present, accept only the
  main thread (`TID == PID`); any other TID returns `Unsupported` and is
  documented. Windows returns `Unsupported`.
* More than six arguments returns `InvalidArgument`/`Unsupported` before any
  target call.
* Pointer arguments are raw target addresses. The caller owns the pointed-to
  memory and its lifetime; v1 does not copy strings, structs, or buffers into
  the target.
* `call_export` resolves with `Process::module_export` and then calls. It must
  reject an export that is not in an executable region.
* `RemoteCaller` is `Send + Sync`, but calls on one instance are serialized with
  an internal mutex.
* `call` is safe Rust with respect to the caller's memory, but can crash or
  corrupt the target. Document that in the same direct language `memdiver` uses
  for writes.
* Reject a read-only `Process` before any OS call.

## 6. Pinning and identity protocol

`memdiver` pins the memory handle but does not expose its raw OS handle or start
time. Do not add such an API to `memdiver`. Use the following protocol.

### `RemoteCaller::open(pid)` — preferred

1. **Windows:** `OpenProcess` with `PROCESS_CREATE_THREAD`,
   `PROCESS_QUERY_INFORMATION`, `PROCESS_VM_OPERATION`, `PROCESS_VM_READ`,
   `PROCESS_VM_WRITE`, and `PROCESS_SYNCHRONIZE`. This handle pins the process
   object.
   **Linux:** `PTRACE_SEIZE` + `PTRACE_INTERRUPT` the main TID and wait for the
   stop with `waitpid(..., __WALL)`.
2. `memdiver::Process::open(pid)`.
3. Check `process.is_alive()` again; if false, close/detach and return
   `TargetExited`.
4. Check `process.pointer_width()` against the host bitness; a mismatch returns
   `Unsupported` before any call (detach/close the execution resource first).
   Same-bitness is a v1 requirement.
5. On Linux, `PTRACE_DETACH` before returning (the target must not stay stopped
   between calls). A failed detach is an error.
6. Keep the Windows execution handle for the lifetime of the caller.

Because the execution resource is acquired first, the PID cannot have been
recycled between the two opens.

### `RemoteCaller::new(process)` — adopt an existing handle

1. Reject `!process.is_writable()` before any OS call.
2. Check `process.is_alive()`; false → `TargetExited`.
3. Check `process.pointer_width()` against the host bitness; a mismatch returns
   `Unsupported`.
4. Open the execution resource by `process.pid()`. On Linux this is a short
   attach/verify/detach handshake, not a persistent stop.
5. Check `process.is_alive()` again; false → close/detach and `TargetExited`.

The post-open liveness check (step 5) is the safety argument: a pinned
`memdiver::Process` is alive only while its instance is running. If the PID was
recycled between steps 2 and 4, the old instance exited and step 5 observes
false. If step 5 is true, the PID still referred to the old instance when the
execution resource was opened.

### Linux per-call attach

`RemoteCaller` must not keep the target stopped between calls. Each `call`:

1. `process.is_alive()`;
2. attach/interrupt the TID;
3. `process.is_alive()` again; false → detach and `TargetExited`;
4. run the call, restore state, detach.

Use the same double-liveness check on every call.

Only the selected Linux thread is stopped/redirected; the target's other threads
keep running. Document the resulting race and deadlock hazard. A function that
assumes the target's main thread or a lock held by another thread can misbehave;
the library cannot solve that generally.

### Windows lifetime

The execution handle stays open for the `RemoteCaller` lifetime. The
`memdiver::Process` is kept for memory I/O. Calls are synchronous, so there is
no in-flight thread when `Drop` runs.

## 7. Windows x86_64 mechanism

Use `CreateRemoteThread` with a generated stub. Required rights:
`PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SYNCHRONIZE`.

Stub layout (validated under Wine):

```text
sub rsp, 0x38                      ; shadow space + args 5/6 + alignment
mov rcx, arg0
mov rdx, arg1
mov r8,  arg2
mov r9,  arg3
mov rax, arg4 ; mov [rsp+0x20], rax
mov rax, arg5 ; mov [rsp+0x28], rax
mov rax, function
call rax
mov [result], rax                  ; absolute result address patched in
; ... also set a completion flag in the same result allocation ...
xor eax, eax
add rsp, 0x38
ret
```

The result allocation should hold at least `{ result: u64, completed: u64 }`.
The stub stores the result and then sets `completed`, so the caller can
distinguish a normal return from a function that called `ExitThread` /
`ExitProcess` without returning through the stub. Patch the allocation address
into the stub (for example, load it into a scratch register and use
`[reg]`/`[reg+8]` stores).

Implementation requirements:

1. Allocate the stub page `PAGE_READWRITE` and the result/completion block in a
   **separate** `PAGE_READWRITE` allocation. Do not put it immediately after
   the stub: `VirtualProtectEx` works on whole pages and the block would become
   read-only.
2. Write the stub through `memdiver::Process::write`; patch the absolute result
   address into the `mov [result], rax` immediate.
3. `VirtualProtectEx` the stub page to `PAGE_EXECUTE_READ` and call
   `FlushInstructionCache`.
4. `CreateRemoteThread` at the stub, `WaitForSingleObject(INFINITE)`,
   `GetExitCodeThread`. The stub must exit with code zero on success; a non-zero
   exit code is an error.
5. Read the result and the completion flag through `memdiver` (for example,
   `Process::read_value::<[u64; 2]>`). A missing flag means the function never
   returned through the stub; return `CallFailed` instead of trusting stale
   memory. This covers a function that calls `ExitThread`/`ExitProcess` with a
   zero thread exit code.
7. Free the result and stub allocations and close thread/handle in every path
   where it is safe. Do not free remote memory while the thread may still run.
8. Validate the function address against an executable live region with
   `Process::region_at` before creating the thread. This is best-effort, not a
   signature check.
9. W^X: never create an RWX page.
10. CFG/CET: an indirect `call rax` is subject to Control Flow Guard. Prefer a
    direct `call rel32` when the stub can be allocated within ±2 GiB of the
    function; otherwise use the indirect form and document the CFG risk. The
    stub uses a real `call`/`ret`, which should be compatible with CET shadow
    stack; native CET testing is still required. Test on native Windows; Wine
    does not enforce CFG. The stub has no `.pdata`, so C++ exceptions crossing
    it are unsupported.
11. Handle rights: if `OpenProcess` is denied, return a precise error. Do not
    retry with fewer rights and then fail later.

## 8. Linux x86_64 mechanism

Use `ptrace` plus a **hardware execution breakpoint**, not an `int3`. This
avoids writing target code and avoids the shared-mapping/W^X problem.

### Attach and state

1. `PTRACE_SEIZE` + `PTRACE_INTERRUPT`, then `waitpid(tid, ..., __WALL)` for the
   stop.
2. Save GP registers (`PTRACE_GETREGS`/`user_regs_struct`), FP/SIMD state
   (`PTRACE_GETREGSET` with `NT_X86_XSTATE` where supported; `NT_FPREGSET` or
   `PTRACE_GETFPREGS` fallback), and `DR0`–`DR7`.
3. Validate with `Process::region_at` that both the function address and the
   interrupted `RIP` are in executable regions before redirecting anything.
   The return address is the interrupted `RIP`. Choose a free hardware
   breakpoint slot among `DR0`–`DR3` (L and G bits clear in `DR7`). Set
   `DRi = RIP`; in `DR7` clear that slot's L/G and RW/LEN fields and set the
   local-enable bit (execute breakpoint: RW=00, LEN=00). Preserve all other
   `DR7` bits.
4. If no slot is free, return a clear error. Do not silently use an `int3`
   fallback in v1.
5. Confirm the hit with `SIGTRAP`, `RIP == breakpoint`,
   `si_code == TRAP_HWBKPT`, and the expected `DR6` bit. Do not mistake a
   target-generated trap for the call return.
6. At the confirmed hit, **clear `DR6` first** (the slot's B0–B3 status bit),
   then restore `DR7`, `DRi`, and the saved `DR6`. On the tested kernel,
   `PTRACE_POKEUSER(DR7)` returns `EIO` while the status bit is set.

### Call frame and red zone

The SysV AMD64 red zone is the 128 bytes below `RSP`; do not touch it. For
`stack_args = 8 * max(0, args.len() - 6)`:

```text
limit = saved.rsp.checked_sub(128 + stack_args)?
frame = ((limit.checked_sub(8)?) & !0xF).checked_sub(8)?
assert frame + 8 + stack_args <= saved.rsp - 128
```

`frame` must be `8 mod 16` so the callee sees the ABI-required
`rsp % 16 == 8` at entry. Put the return address at `frame` and arguments 7+ at
`frame + 8`, `frame + 16`, ... . Verify with `Process::region_at` that the
**whole frame range** is writable and that the stack region has at least 4 KiB
of headroom below it. That headroom is a guard band, not a proof that the
callee's full stack usage fits.

Write the return address and stack arguments in one
`memdiver::Process::write` call. Sanitize `rflags`: clear `DF` and `TF` at
minimum (the ABI requires `DF = 0` at function entry).

### Resume and restore

1. Set `RIP = function`, `RSP = frame`, and the argument registers
   (`RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9`).
2. Set `orig_rax = -1` (`u64::MAX`) to cancel a pending syscall restart.
3. `PTRACE_CONT`, then wait for the breakpoint.
4. On the breakpoint, read `RAX` as the result.
5. Restore GP registers, FP/XSTATE, and debug registers on every path.
6. `PTRACE_DETACH` with signal 0. A failed detach is an error.
7. Forward non-breakpoint signals with `PTRACE_CONT(signal)` and keep waiting.
   If the target exits or is killed, return `TargetExited`/`CallFailed` rather
   than pretending the call succeeded. C++ exceptions/`longjmp` through the fake
   frame are unsupported.

### CET shadow stack

Detect SHSTK for the target (for example from `/proc/<pid>/status`'s
`x86_Thread_features` / `x86_Thread_features_locked` fields). If SHSTK is
enabled, return `Unsupported` in v1: the fake-return technique does not create a
shadow-stack entry, so the callee's `ret` can fault. Do not assume CET is absent
on a modern Linux target.

### Safety

* `PTRACE_SEIZE` can fail with `EPERM`/`EBUSY`; report it and do not fight an
  existing tracer.
* Yama `ptrace_scope`, `PR_SET_PTRACER`, `CAP_SYS_PTRACE`, seccomp, user
  namespaces, and container capabilities apply. Tests use a child process, so
  they work under normal `ptrace_scope=1`.
* If the caller is killed with `SIGKILL` during a call, the target can remain
  stopped. Do not set `PTRACE_O_EXITKILL` by default; document the operational
  consequence.
* The thread-group leader may be gone while other threads remain; `PTRACE_SEIZE`
  by PID then fails. Report it; do not silently pick another thread.
* If the target `execve`s during the call, `memdiver` reports
  `AddressSpaceReplaced`; treat the call as failed, detach, and do not keep
  using the old TID/address space.

## 9. Error and cleanup model

Define a new non-exhaustive error type in `memdiver-call`. Do not extend
`memdiver::Error`. Keep context and raw OS codes.

Required distinctions:

* `Open` — execution resource or memory handle failed;
* `ReadOnly` — handle not writable, before any OS call;
* `TargetExited` — target exited or PID reused;
* `Unsupported` — platform, ABI, architecture, argument count, etc.;
* `InvalidAddress` — function/return/stack address not usable;
* `InvalidArgument` — unsupported value or ABI argument;
* `Platform` — OS call failed, with raw code and operation name;
* `CallFailed` — call ran but did not produce a normal integer result
  (non-zero thread exit, unexpected signal, target death);
* `Cleanup` — restore/detach/free failed; keep `call: Option<Box<Error>>` and
  `cleanup: Box<Error>`.

Cleanup requirements:

* Linux: a guard restores registers/debug state and detaches even if setup
  fails. If restore and detach both fail, report a composite.
* Windows: a guard closes thread/handle and frees stub/result only after the
  thread has exited. If the wait fails, do not free memory that a running thread
  could still use; report the leak in the error/context.
* Never return `Ok` after a short write, a failed restore, or a failed detach.
* A poisoned internal mutex is an error, not a panic.

## 10. Testing

Use `memdiver-call-tests` with a fixture child. The fixture:

* prints a `READY` line containing its PID and the addresses of its callable
  functions;
* blocks reading stdin;
* answers `PING` with `PONG` between calls;
* exposes `#[no_mangle] extern "C"` functions:
  * `fixture_add(a, b) -> u64`;
  * `fixture_mix(a..f) -> u64`;
  * `fixture_store(ptr, value)` — writes to a buffer the parent can read;
  * `fixture_ping() -> u64`;
  * `fixture_exit()` — controlled target exit.
* never touches its buffer while the parent is reading it (except during
  `fixture_store`, which is the point of that test).

Unit tests (pure logic, no OS):

* Windows stub bytes: exact instruction sequence, stack offsets, result-address
  patching, and argument-count bounds.
* Linux frame math: red zone, checked arithmetic, 16-byte alignment, stack
  argument placement.
* Hardware breakpoint slot selection and `DR7` bit manipulation.
* Error formatting and composite cleanup construction.

Integration tests (through the public API only):

* `open` and `new` both work;
* 2- and 6-argument calls, and a zero-argument call;
* pointer argument + read back the target-written value through `memdiver`;
* `call_export` on a fixture export (if the fixture can export one reliably);
* read-only handle → `ReadOnly` before any OS call;
* target exit during `call_exit` → error, not a hang;
* unsupported ABI/architecture/argument count → `Unsupported`;
* Linux: call while the fixture is blocked in `read(2)`, then `PING` to prove
  the fixture resumed (the `orig_rax` regression);
* Linux: two consecutive calls;
* Windows: x64 under Wine locally if available, and native Windows in CI;
* concurrent calls through one `RemoteCaller` are serialized and both return
  correct results;
* no test intentionally calls a bad address or a mismatched ABI.

Do not mark failing tests `#[ignore]`. If a platform cannot run a test locally,
state that in the final report and add it to CI.

## 11. Documentation

Write a real README, not a stub:

* what the library does and the exact v1 feature matrix;
* platform permissions/requirements (Windows `OpenProcess` rights; Linux
  ptrace/Yama);
* safety warning: the call can crash or corrupt the target; the library cannot
  validate a function signature;
* limitations: no timeout/cancellation; Linux CET SHSTK unsupported; no x86/
  ARM64/cross-bitness; no floating-point/struct/variadic arguments; no remote
  allocation; any CFG/CET status that is not natively tested;
* observability: remote thread creation, `TracerPid`, target timing changes;
* security/ethics: authorized use only;
* a minimal example that does not require a real game (spawn a fixture child or
  use a documented test program).

Rustdoc every public item; the safe crate should use `#![deny(missing_docs)]`.

## 12. Quality gate and CI

Run and report all of these:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps
cargo check --workspace --all-targets --target x86_64-pc-windows-gnu
cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu -- -D warnings
cargo package --list -p memdiver-call
cargo package --list -p memdiver-call-sys
```

CI should include:

* Linux x64 tests (child ptrace; ordinary user);
* Windows x64 native tests;
* Windows cross-check/clippy from Linux if native Windows is unavailable;
* an MSRV check;
* no generated artifacts committed.

If native Windows is unavailable, say so explicitly; do not claim CFG/CET/EDR
behaviour was verified under Wine.

## 13. Non-goals

Do not implement:

* network RPC, HTTP, or sockets;
* DLL/`.so` injection for its own sake;
* kernel drivers or hypervisor tricks;
* a debugger UI, attach-to-all-threads mode, or thread hijacking;
* timeout/cancellation in v1;
* general target allocation, string/struct marshalling, or float/SIMD/vararg
  calls in v1;
* x86 support in the required v1 matrix (it is only an optional, tested stretch
  goal), ARM64, and cross-bitness support.

## 14. Acceptance checklist

The task is done only when all of these are true:

- [ ] `memdiver` is an ordinary dependency; no `memdiver` files were changed.
- [ ] The new project builds as an independent workspace.
- [ ] Safe crate is `#![forbid(unsafe_code)]`; all unsafe is in the sys crate
      with `SAFETY` comments.
- [ ] `RemoteCaller::open`, `new`, and `call` work on Linux x64; `call_export`
      is implemented and covered by an integration or resolver test.
- [ ] Windows x64 `call` works (native CI, or Wine locally with the limitation
      stated).
- [ ] Both pin orderings work, and the Linux per-call double-liveness path is
      tested.
- [ ] Linux calls work while the fixture is blocked in `read(2)` and the fixture
      answers `PING` afterwards.
- [ ] Read-only handles, target exit, unsupported ABI/arch, and invalid
      addresses return structured errors without panics.
- [ ] No RWX page is created on Windows; the result/completion block has its
      own allocation.
- [ ] Linux uses the hardware-breakpoint path by default, acknowledges `DR6`
      before restoring `DR7`, and refuses CET SHSTK.
- [ ] Timeouts/cancellation are documented as unsupported, not silently
      half-implemented.
- [ ] README, rustdoc, CHANGELOG, and licenses are present.
- [ ] Formatting, clippy (host + Windows target), tests, and docs pass.
- [ ] Work is committed locally in focused commits; nothing is published.

## 15. Suggested order of work

1. Scaffold the independent workspace and crate skeletons.
2. Define the public API and error model; write the README feature matrix.
3. Implement `memdiver-call-sys` for Linux: attach, registers, hardware
   breakpoint, frame, restore, detach.
4. Implement `memdiver-call-sys` for Windows: handle, allocations, stub,
   protection, thread, wait, free.
5. Implement the safe orchestration and pinning protocol.
6. Add the fixture and unit tests for the pure layout/stub logic.
7. Add end-to-end tests on Linux, then Windows.
8. Run the full quality gate; fix warnings and failures.
9. Review the diff for unsafe/cleanup/error-path mistakes.
10. Write the final report and commit.

## 16. Final report

When finished, report:

* repository/commit hash and crate names;
* exact public API and supported matrix;
* test commands and results (Linux, Windows native/Wine, cross-check);
* what was validated and what was not;
* known limitations and any deviations from this brief;
* whether any `memdiver` public-API gap was found (do not patch it);
* confirmation that nothing was published.
