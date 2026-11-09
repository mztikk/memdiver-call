# Changelog

All notable changes to `memdiver-call-sys` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-11-09

### Changed

- Upgrade the `memdiver` dependency from 0.2 to 0.3.0. The backend uses only the
  stable `Process`, `Address`, and `RegionMap` facade; no source changes were
  needed, and the public `memdiver-call-sys` API is unchanged.

## [0.2.0] - 2026-11-09

### Changed (breaking)

- `windows::Abi` and `wine32::WineAbi` are replaced by one `Abi` enum.
- `CallStatus` is `#[non_exhaustive]`.
- `linux::wait_for_breakpoint` takes the synthetic frame address so it can
  distinguish the real return from the callee executing the interrupted
  instruction; `Attached::call` and `CallOutcome` are `must_use`.
- The attach guards store the saved debug-register state and restore it before
  detaching on unwind.
- Removed `is_supported`, which was always true wherever the crate compiled.

### Fixed

- The xstate buffer is sized from the kernel instead of a fixed 4 KiB.
- The call frame must lie in the interrupted stack region.
- Safe-point waits check the deadline on every iteration, forward genuine
  signals only, bound the post-timeout interrupt wait, and distinguish a
  running tracee from a dead one on `PTRACE_DETACH` `ESRCH`.
- The x64 stub zeroes `AL` before the call and carries the indirect target in
  `R11`; both stubs start with `ENDBR64`/`ENDBR32`.
- The Windows leak is reported before closing the thread handle.
