# Changelog

All notable changes to `memdiver-call` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Size the saved xstate from the kernel instead of a fixed 4 KiB buffer; on
  AMX-class CPUs the previous buffer was truncated and restoring it failed.
- Disambiguate early return-breakpoint hits with the stack pointer and the
  resume flag, so calling the function the thread is executing returns its
  result instead of a stale register.
- Check the safe-point deadline on every iteration, bound forwarded stops and
  the post-timeout interrupt wait, classify job-control stops, preserve a
  pending signal when detaching after a failure, and stop treating `ESRCH`
  from `PTRACE_DETACH` as "already detached".
- Restore the saved debug registers from the attach guard on unwind;
  `CallOutcome` is now `must_use`.
- Report a Windows leak before closing the thread handle so a close failure
  cannot mask an abandoned allocation.
- Zero `AL` in the x64 stub for variadic callees and carry the indirect target
  in `R11`.
- Correct the documented error sets, narrow-return contract, and native
  Linux/Wine limitations.

### Changed

- Use one region-map snapshot per call instead of up to five `region_at`
  calls, and require the call frame to be in the interrupted stack region.
- One `Abi` enum in `memdiver-call-sys`; `windows::Abi` and `wine32::WineAbi`
  are merged into it. `memdiver-call-sys::CallStatus` is non-exhaustive.
- Re-export `Address` and `Process` from `memdiver-call`; add
  `RemoteCaller::wine_module_base`; the attach guard is panic-safe.

### Removed

- `memdiver_call_sys::is_supported` (it was always true where the crate
  compiles).

## [0.1.1] - 2026-11-09

### Changed

- Documentation-only release: the README now records the crates.io release,
  adds install and documentation links, and no longer claims the crate is
  unpublished. No API or behaviour changes.

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
- Native Linux `x86_64` → 32-bit Windows PE under Wine:
  `RemoteCaller::open_wine`/`new_wine`, a native `ptrace` backend in 32-bit
  compatibility mode, the Windows `x86` calling conventions, `EDX:EAX`
  results, hardware-breakpoint safe points (`with_safe_point`,
  `with_safe_point_timeout`, `Error::SafePointTimeout`), and 64-bit stack
  arguments (`CallOptions::with_wide_arguments`, two dwords low-first).
- 64-bit stack arguments on native Windows `x86` through the generated stub;
  the shared x86 layout rejects 64-bit register arguments.
- `CallAbi` (`Auto`, `Cdecl`, `Stdcall`, `Thiscall`, `Fastcall`) and
  `CallOptions` with ABI, Linux main-thread selection, and Wine safe points.
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
- Native-Linux-to-Wine calls do not support `call_export` (PE exports are
  unavailable to `memdiver` on Linux) and only support the main thread; a safe
  point is required whenever the thread is not stopped in 32-bit code.
- 64-bit arguments are supported only in stack positions; the `thiscall`
  `this` and the two `fastcall` register arguments must be 32-bit.
- Native Windows CFG/CET behaviour is not verified by this release's local
  tests; native Windows CI is configured for it.
