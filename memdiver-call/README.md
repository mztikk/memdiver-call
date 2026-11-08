# memdiver-call

Call a function inside another local process on **Linux `x86_64`** and
**Windows `x86_64` / `x86`**.

It also reaches a **32-bit Windows PE hosted by Wine** from a **native Linux
`x86_64`** caller, which is the usual setup for a Linux tool driving a 32-bit
Windows game.

`memdiver-call` is an independent library built on the public
[`memdiver`](https://crates.io/crates/memdiver) facade. `memdiver` performs
process discovery, pinning, memory reads and writes, region queries, modules,
and export resolution; `memdiver-call` adds the execution mechanism that
`memdiver` deliberately omits. The `memdiver` crate is not modified, forked, or
vendored.

```rust
use memdiver::Address;
use memdiver_call::{CallOptions, RemoteCaller};

let caller = RemoteCaller::open(pid)?;
let result = caller.call(Address::new(address), &[1, 2], &CallOptions::new())?;
```

## How it works

| Platform | Mechanism |
|----------|-----------|
| Linux `x86_64` | `ptrace` attaches to the target's main thread, a **hardware execution breakpoint** is placed at the interrupted instruction, `RIP`/`RSP` and the argument registers are redirected, and the full thread state is restored. No target code is written. |
| Windows `x86_64` / `x86` | A generated machine-code stub is written into a remote `PAGE_READWRITE` page, changed to `PAGE_EXECUTE_READ`, and run with `CreateRemoteThread`. The stub stores the result and a completion flag in a **separate** writable allocation. |
| Native Linux `x86_64` → 32-bit Windows PE under Wine | `ptrace` attaches to the PE-hosting process, waits for a **safe-point** hardware breakpoint in 32-bit code, redirects `EIP`/`ESP` with the Windows `x86` ABI, and uses the same breakpoint for the return. |

Both mechanisms are invasive and observable; see
[Observability](#observability). This is not network RPC and not DLL/`.so`
injection for its own sake.

## Feature matrix (v1)

| Capability | Linux `x86_64` | Windows `x86_64` | Windows `x86` |
|---|:---:|:---:|:---:|
| `RemoteCaller::open` / `new` | yes | yes | yes |
| `call` / `call_export` | yes | yes | yes |
| Same-bitness target | yes | yes | yes |
| 0–6 integer/pointer arguments (`u64` slots) | yes | yes | yes (each value must fit in 32 bits) |
| Integer/pointer return as `u64` | yes | yes | yes (`EDX:EAX`) |
| `Auto` ABI | SysV AMD64 | Microsoft x64 | `cdecl` |
| `cdecl` | — | — | yes |
| `stdcall` | — | — | yes |
| `thiscall` | — | — | yes |
| `fastcall` | — | — | yes |
| Main-thread selection (`with_thread(pid)`) | yes | no | no |
| CET shadow stack (`SHSTK`) target | refused | — | — |
| Timeout / cancellation | no | no | no |
| Cross-bitness / WOW64 | no | no | no |
| ARM64 | no | no | no |
| Floating-point, SIMD, struct-by-value, variadic | no | no | no |
| General remote allocation / string marshalling | no | no | no |

Anything outside the matrix returns `memdiver_call::Error::Unsupported` or is
not part of the API. Cross-bitness targets are rejected during `open`/`new`
except for the explicit native-Linux-to-Wine-`x86` mode below.

### Native Linux `x86_64` → 32-bit Windows PE under Wine

| Capability | |
|---|:---:|
| `RemoteCaller::open_wine` / `new_wine` | yes |
| `call` with 0–6 arguments, each fitting in 32 bits | yes |
| `cdecl` / `stdcall` / `thiscall` / `fastcall` | yes |
| `u64` result (`EDX:EAX`) | yes |
| `with_safe_point` | yes; required whenever the thread stop is not already in 32-bit mode |
| `with_thread` beyond the main thread | no |
| 64-bit arguments | no |
| `call_export` | no; pass the function address |
| Host | Linux `x86_64` only |

### Return values on Windows `x86`

The generated 32-bit stub stores `EDX:EAX` as the `u64` result. For a function
that returns a 32-bit integer, only the low 32 bits are meaningful; use the low
half. A function returning a 64-bit integer uses the full value. Calls that
need to pass a 64-bit argument are not supported on `x86`; each argument slot
must fit in 32 bits and larger values are rejected with
`Error::InvalidArgument`.

## Calling a 32-bit Windows process under Wine

Wine runs 32-bit PE code natively in 32-bit compatibility mode and maps the PE
at its Windows virtual addresses, so a normal `ptrace` attachment can redirect
the thread. `RemoteCaller::open_wine` uses the same hardware-breakpoint
mechanism as the Linux backend and never writes target code.

```rust
use memdiver::Address;
use memdiver_call::{CallAbi, CallOptions, RemoteCaller};

let caller = RemoteCaller::open_wine(pid)?;
let options = CallOptions::new()
    .with_safe_point(Address::new(swap_buffers_return))
    .with_abi(CallAbi::Thiscall);
let result = caller.call(Address::new(function), &[this, event_time], &options)?;
```

**The PID must be the process that hosts the PE**, not the `wine` launcher.
Its Linux command line contains the `.exe` path (for example
`Z:\...\game.exe`). If you spawn Wine yourself, call
`prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)` **before** spawning: Wine forks the
PE host and reparents it, and Yama `ptrace_scope = 1` only allows tracing
descendants. Games started by Steam/Proton may run in a different PID namespace
and cannot be reached from outside their container.

### Safe points

A thread stopped inside a Wine syscall is in 64-bit mode (`CS = 0x33`) and must
not be redirected to 32-bit PE code. A safe point is an instruction address in
32-bit code that the main thread reaches regularly: the instruction after
`SwapBuffers` returns, the loop back-edge, or a per-frame tick entry. The
backend arms a hardware execution breakpoint there, resumes the target until it
arrives, performs the call, and uses the same breakpoint for the return. The
wait is bounded by `with_safe_point_timeout` (default five seconds) and reports
`Error::SafePointTimeout` when the target does not reach the point (for
example while minimized, paused, or loading).

Without a safe point the call is only attempted if the thread happens to be
stopped in 32-bit mode; otherwise it returns `Error::Unsupported`. That mode is
useful for tests and simple targets, not for a live game main thread.

### Wine-specific limitations

- Arguments are 32-bit; a slot above `u32::MAX` is rejected. 64-bit arguments
  would need two stack slots and are not supported yet.
- `call_export` returns `Error::Unsupported`; PE exports are not available to
  `memdiver` on Linux. Pass the function address.
- The called function runs on the game's main thread with its TEB, locks, and
  thread-local state. SEH/C++ exceptions that unwind through the synthetic
  frame are unsupported.
- Only the main thread (`TID == PID`) can be selected.
- A call that never returns hangs the caller; there is no cancellation.
- Nothing is bounded except the safe-point wait; the call itself has no
  timeout.

## Requirements

### Linux

* Permission to `ptrace` the target. With Yama
  `kernel.yama.ptrace_scope = 1` (the common default) a normal user can trace a
  descendant process; tracing an unrelated process needs `CAP_SYS_PTRACE` or
  `PR_SET_PTRACER`.
* The target must not already be traced by another debugger; `PTRACE_SEIZE`
  fails with `EPERM`/`EBUSY` and the error is reported, never retried.
* A kernel with `ptrace(PTRACE_SEIZE)` support and x86 debug registers. If the
  target uses all four hardware breakpoints, the call fails with
  `Error::Unsupported` rather than falling back to `int3`.
* Targets with CET shadow stack (`SHSTK`) enabled are refused: the fake-return
  technique does not create a shadow-stack entry, so the callee's `ret` would
  fault.
* For a Wine 32-bit target: the caller must be able to `ptrace` the PE-hosting
  process. A caller that spawns Wine should be a child subreaper so the
  reparented PE process stays a descendant; otherwise Yama, a different PID
  namespace (Proton/pressure-vessel), or an existing tracer makes the attach
  fail with `Error::Open`.

### Windows

`OpenProcess` requests:

```text
PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SYNCHRONIZE
```

`memdiver` opens its own handle for memory I/O and does **not** request
`PROCESS_CREATE_THREAD`. If the execution handle is denied, the call fails with
`Error::Open` carrying the raw `GetLastError` code; the request is never
retried with fewer rights. Protected or higher-integrity processes therefore
need an elevated caller.

## Safety

The API is safe Rust with respect to the caller's own memory, but a remote call
can **crash or corrupt the target**. The library cannot validate a function
signature, a calling convention, an argument layout, or the side effects of the
called code. Pointer arguments are raw target addresses; the caller owns the
pointed-to memory and its lifetime. v1 does not copy strings, structs, or
buffers into the target.

Deadlock is possible: on Linux the target's main thread is redirected, so a
function that needs a lock held by another thread — or that assumes it runs on
that thread or with its thread-local state — can misbehave. On Windows the call
runs on a fresh thread, which has the opposite threading assumptions. The
library cannot solve that generally.

Use this only on processes you own or are explicitly authorized to inspect.

## Limitations

* **No timeout and no cancellation.** A call that never returns hangs the
  caller. There is no safe way to abort a function call in another process;
  `TerminateThread` and detaching a half-executed call are deliberately not
  offered. A hung call is the caller's operational problem.
* **Linux CET shadow stack is unsupported.** Detected and refused.
* **No native Windows CFG/CET verification.** The stub prefers a direct
  `call rel32` (not subject to Control Flow Guard and not an IBT indirect
  branch) and falls back to an indirect `call rax` when it cannot be allocated
  within ±2 GiB of the function. Wine does not enforce CFG/CET, so this
  project's local Windows tests cannot prove those mitigations; native Windows
  CI is configured.
* **No unwind metadata in the Windows stub.** C++ exceptions that unwind
  through the stub are unsupported and can terminate the target.
* **Linux `x86`, ARM64, cross-bitness, and WOW64** are unsupported.
* **Only the main Linux thread** can be selected; any other TID is
  `Unsupported`.
* **No floating-point, SIMD, struct-by-value, variadic, or C++
  `thiscall`-on-`x86_64`** argument support.
* **No general remote allocation** or string/struct marshalling.
* **The call is synchronous** and runs to completion; there is no
  `RemoteCall` handle.
* **Wine 32-bit targets**: no 64-bit arguments, no `call_export`, only the main
  thread, and a safe point is required whenever the thread is not stopped in
  32-bit code. Safe-point waiting is bounded; the call is not.
* **Signals:** non-breakpoint signals received by the traced Linux thread
  during a call are forwarded, and the call fails if the target dies. A signal
  storm is bounded and fails the call rather than hanging.
* **Target death during setup or call** is reported as
  `Error::TargetExited`/`Error::CallFailed`, never as success.
* **A killed caller can leave a Linux target stopped.** If the calling process
  is `SIGKILL`ed during a call, the tracee can remain stopped. `PTRACE_O_EXITKILL`
  is not set by default because killing the target is usually worse.

## Cleanup and errors

Every path restores target state, detaches, closes handles, and frees remote
memory. A cleanup failure is never hidden: `Error::Cleanup` keeps the call
failure in `call` and the cleanup failure in `cleanup`. A call is never
reported as `Ok` after a short transfer, a failed restore, or a failed detach.
A poisoned internal mutex returns `Error::Poisoned` instead of panicking.

On Windows, if the wait for the remote thread fails, the thread may still be
running; the stub/result allocations are deliberately **not** freed (freeing
memory a running thread may touch is a use-after-free) and the leak is
reported as `Error::Leaked`.

## Observability

The operation is not stealthy:

* **Linux:** `/proc/<pid>/status` shows a `TracerPid` while the call runs, one
  thread is stopped and redirected, the debug registers are modified, and an
  in-flight syscall can return `EINTR` (this library sets `orig_rax = -1` to
  cancel a restart, and the fixture tests exercise a target blocked in
  `read(2)`). Target timing and scheduling change.
* **Windows:** a new thread appears in the target (thread-creation telemetry,
  loader/thread-attach notifications, changed timing and memory layout). The
  visible process has new private executable memory only for the duration of
  the call.

## Security and ethics

Remote function invocation is a dual-use primitive: it is legitimate for
debugging, modding with consent, automation of software you own, and research,
and it is also a standard malware technique. This library takes the operating
system's permission model as the only access boundary. Use it only on
processes you own or are explicitly authorized to inspect, and treat the
ability to call into a process as equivalent to the ability to run code in it.

## Example

The workspace contains a runnable example that spawns the test fixture and
calls one of its functions:

```sh
cargo build --workspace
cargo run -p memdiver-call-tests --example call_fixture
```

The library-side code is:

```rust,no_run
use memdiver::Address;
use memdiver_call::{CallOptions, RemoteCaller};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let caller = RemoteCaller::open(1234)?;
let value = caller.call(Address::new(0x7f00_0000_1000), &[2, 3], &CallOptions::new())?;
println!("remote result: {value}");
# Ok(())
# }
```

To try it against your own program, compile a C or Rust child with an
`extern "C"` function, print the function's address and PID, keep the child
running, and pass those values to `RemoteCaller`. Never point the API at a
process you do not own.

## Testing

```sh
cargo test --workspace
```

End-to-end tests spawn a fixture child, resolve its function addresses, call
them through the public API, and verify the child still answers `PING` after
every call. The Linux tests run the fixture blocked in `read(2)` (the
`orig_rax` regression), two consecutive calls, pointer arguments, a target that
exits during a call, concurrent calls through one caller, and `call_export`
including the non-executable data-export rejection.

Windows `x86_64` and `x86` tests run under Wine locally:

```sh
WINEPREFIX="$PWD/.wine-x64" WINEDEBUG=-all \
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine \
    cargo test --workspace --target x86_64-pc-windows-gnu
WINEPREFIX="$PWD/.wine-wow64" WINEDEBUG=-all \
    CARGO_TARGET_I686_PC_WINDOWS_GNU_RUNNER=wine \
    cargo test --workspace --target i686-pc-windows-gnu
```

The prefixes are created inside the workspace and are ignored by Git.

### Wine 32-bit tests

The native-Linux-to-Wine tests are opt-in because they need Wine, MinGW, and a
prebuilt i686 fixture:

```sh
cargo build -p memdiver-call-tests --target i686-pc-windows-gnu \
    --bin memdiver-call-fixture
WINEPREFIX="$PWD/target/wine32-test-prefix" WINEDEBUG=-all \
    cargo test -p memdiver-call-tests --features wine32-tests --test wine32
```

They spawn a 32-bit Windows fixture under Wine with a spin-loop tick, find the
PE-hosting process as a child subreaper, and exercise the safe point,
`cdecl`/`stdcall`/`thiscall`/`fastcall`, pointer arguments, timeout, target
exit, and serialized concurrent calls.

## MSRV and licensing

Rust 1.85 (edition 2024). Licensed under MIT OR Apache-2.0.

## Version

`0.1.0` — the first release. It is not published to crates.io.
