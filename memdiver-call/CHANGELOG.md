# Changelog

All notable changes to `memdiver-call` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-08

### Added

- `RemoteCaller::open(pid)` and `RemoteCaller::new(Process)` with the documented
  pinning protocols (execution resource first, or double-liveness checks around
  the execution resource) and a writable-handle check.
- `RemoteCaller::call` and `RemoteCaller::call_export` for up to six
  integer/pointer arguments and one `u64` result.
- Linux `x86_64` backend: `PTRACE_SEIZE`/`PTRACE_INTERRUPT`, red-zone-safe call
  frame, hardware execution breakpoint, full GP/FP/XSTATE and debug-register
  save/restore, `DR6` acknowledgement before `DR7` restore, `orig_rax`
  invalidation, signal forwarding, CET SHSTK refusal, and detach on every path.
- Windows `x86_64` and `x86` backend: generated stubs, separate RW stub and
  result allocations, W^X protection transitions, `CreateRemoteThread`, thread
  exit-code and completion-flag checks, CFG-friendly direct calls when in range,
  and leak reporting when the thread cannot be proven stopped.
- `CallAbi` (`Auto`, `Cdecl`, `Stdcall`, `Thiscall`, `Fastcall`) and
  `CallOptions` with ABI and Linux main-thread selection.
- Structured `Error` with `Open`, `ReadOnly`, `TargetExited`, `Unsupported`,
  `InvalidAddress`, `InvalidArgument`, `Platform`, `Memory`,
  `ExportNotFound`, `CallFailed`, `Cleanup`, `Leaked`, and `Poisoned`.
- `memdiver-call-tests` fixture and end-to-end tests for both platforms,
  including pointer arguments, export resolution, data-export rejection,
  target exit during a call, serialized concurrent calls, the blocked-in-`read`
  Linux path, and a `Send + Sync` assertion.
- Unit tests for the Windows stub bytes (x64 and x86, all conventions), Linux
  frame layout, debug-register selection, and error composition.
- README, rustdoc, dual MIT/Apache-2.0 licenses, and CI for Linux, native
  Windows, Wine cross-tests, and MSRV.

### Known limitations

- No timeout, cancellation, asynchronous calls, or thread hijacking.
- Linux CET shadow stack targets are refused.
- No ARM64, Linux `x86`, cross-bitness, or WOW64 support.
- No floating-point/SIMD/struct/variadic arguments and no general remote
  allocation.
- Native Windows CFG/CET behaviour is not verified by this release's local
  tests; native Windows CI is configured for it.
