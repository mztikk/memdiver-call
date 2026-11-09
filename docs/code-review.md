# Code review: `memdiver-call` workspace

Reviewed tree: commit `8c980d3` (workspace revision at review time, clean working tree).
Reviewer: automated senior-level review; every claim below was checked against the code in
this tree and, where practical, against the running test suites.

## Scope

| Crate | Files reviewed |
|---|---|
| `memdiver-call` | `src/lib.rs`, `src/caller.rs`, `src/error.rs`, `src/options.rs`, `README.md`, `CHANGELOG.md`, `Cargo.toml` |
| `memdiver-call-sys` | `src/lib.rs`, `src/linux.rs`, `src/windows.rs`, `src/wine32.rs`, `src/stub.rs`, `src/frame.rs`, `src/frame_x86.rs`, `src/debug.rs`, `src/x86_args.rs`, `src/error.rs`, `README.md`, `Cargo.toml` |
| `memdiver-call-tests` | fixture, `tests/common/mod.rs`, `tests/remote_call.rs`, `tests/wine32.rs`, `build.rs`, example |
| Workspace | `Cargo.toml`, `rust-toolchain.toml`, `.github/workflows/ci.yml`, `.gitignore`, root `README.md` |

## Verdict

This is a strong, unusually well-tested implementation. The layering is deliberate, the
unsafe code is small, documented and disciplined, the error/cleanup model is thought through,
and the test matrix (native Linux, Windows MSVC/GNU, Wine `x86_64`/`x86`, and native
Linux → Wine `x86`) actually runs. All quality gates pass locally.

The findings below are therefore mostly about **hardening edge cases, removing duplication,
and keeping documentation exact**, not about a broken design. The items I would fix before
calling this production-hardened are the **per-call region enumeration cost**, the **xstate
sizing**, the **missing `function == saved.rip` guard**, and the **frame-region check**.

### Verification performed

All commands were run in this checkout; the working tree was clean before and after (the
temporary probe tests described in the appendix were removed).

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | pass |
| `cargo test --workspace` | 16 + 39 unit + 19 integration + 1 doc test pass |
| `cargo test --workspace --release` | pass |
| `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps` | pass |
| `cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu -- -D warnings` | pass |
| `cargo clippy --workspace --all-targets --target i686-pc-windows-gnu -- -D warnings` | pass |
| `cargo test --workspace --target x86_64-pc-windows-gnu` under Wine | all lib tests + 18 end-to-end tests pass |
| `cargo test --workspace --target i686-pc-windows-gnu` under Wine | all lib tests + 19 end-to-end tests pass |
| `cargo test -p memdiver-call-tests --features wine32-tests --test wine32 -- --test-threads=1` under Wine | 12 tests pass |
| `cargo package --list -p memdiver-call`, `... -p memdiver-call-sys` | pass |
| `#![forbid(unsafe_code)]` in the safe crate; no `unsafe` outside `memdiver-call-sys` | confirmed |
| No `unwrap`/`expect`/`panic!` in non-test library code | confirmed |
| Every `unsafe` block in `memdiver-call-sys` has a `SAFETY:` rationale | confirmed |

MSRV 1.85 could not be re-checked offline (the 1.85 toolchain is not installed and rustup
cannot write to `~/.rustup` in this sandbox); CI runs that job. The code uses nothing newer
than 1.85 by inspection (`offset_of!` 1.77, `is_some_and` 1.70, edition 2024).

### Measurements taken

On this machine (Linux 7.3.3, release build, small 32-region fixture):

* one native `call` ≈ **96.6 µs**;
* `Process::region_at` ≈ **13.2 µs** per call (it re-enumerates `/proc/<pid>/maps`);
* `Process::is_alive` ≈ **1.5 µs**.

The native call path performs **four** `region_at` enumerations per call
(`validate_native` → `require_executable(function)`; then `linux::execute` →
`ensure_executable(function)`, `ensure_executable(saved.rip)`, `ensure_frame`). That is
≈ **53 µs**, i.e. **~55 % of the per-call time on a 32-region process**, and the cost grows
with the number of VMAs of the real target. The Wine32 path does **five** enumerations.

---

## Findings

Severity: **P1** = fix before relying on this in production; **P2** = should fix;
**P3** = cleanup/nit.

### P1 — Correctness / robustness

#### 1. Per-call region enumeration dominates call cost (performance)
`memdiver-call/src/caller.rs:366`, `memdiver-call-sys/src/linux.rs:205-220,687`,
`memdiver-call-sys/src/wine32.rs:358-379,758`

`Process::region_at` is documented by `memdiver` as re-enumerating the process each time
("Prefer [`Process::region_map`] over repeated `region_at` calls"), and each backend calls it
several times:

* native Linux: 4 enumerations/call;
* Wine32: 5 enumerations/call (the function and the safe point are each checked twice, plus
  the frame);
* Windows: 1 (the safe crate's check only; the sys crate trusts the address).

Measured above: ~55 % of a native call on a 32-region process. On a game with hundreds or
thousands of mappings this is likely larger than the ptrace work itself.

**Fix:** build one `Process::region_map()` per phase (one before attach for the cheap
"reject before touching the target" guarantee, one after attach for the TOCTOU-sensitive
checks) and pass the post-attach snapshot to `linux::execute` so `function`, `saved.rip` and
the frame are all checked against the same data; likewise for the Wine32 backend. That turns
4–5 enumerations into 2. Longer term, a `RemoteCaller`-owned snapshot with explicit
invalidation would turn it into 0 or 1 for repeated calls, at the cost of staleness if the
target changes mappings.

#### 2. xstate buffer is a fixed 4 KiB and the fallback silently degrades state restoration
`memdiver-call-sys/src/linux.rs:49-50,470-515`

`get_fp_state` allocates a fixed `XSTATE_BUFFER_SIZE = 4096` and tries `NT_X86_XSTATE` then
`NT_PRFPREG`. The legacy `NT_PRFPREG` set (512 bytes) covers x87/SSE only. The kernel's
regset path clamps the copy to `min(iov_len, fpu_user_cfg.max_size)` and reports the clamped
length, and `xstateregs_set` rejects anything but the full architectural size (`EFAULT`). So
on a CPU whose user xstate exceeds 4 KiB — most notably Intel AMX (`XTILEDATA` = 8 KiB,
total ≈ 11 KiB) — the GET succeeds *truncated* (the fallback never triggers, and `FpState.len`
hides the truncation), while the SET is rejected. The result is that **not even x87/SSE state
is restored**, the interrupted thread's FP/SIMD state stays clobbered, and every call on such
a target is reported as `Error::Cleanup` (or worse, reported as a successful call if the
restore failure is ever downgraded). This is the most likely real-hardware failure mode, not
just a theoretical AMX edge.

**Fix:** query the kernel for the real user-xstate size (one `PTRACE_GETREGSET` with a
> 64 KiB buffer, read back the clamped `iov_len`, allocate exactly that, then GET again), and
validate that the length returned by the size probe matches what the restore will send. Keep
`NT_PRFPREG` only as an explicit fallback when `NT_X86_XSTATE` is genuinely unsupported
(`EINVAL`/`EOPNOTSUPP`), and document what it loses. The constant's comment ("Maximum size of
the extended xstate area") is also factually wrong for AMX.

#### 3. Frame validation does not require the frame to be in the interrupted stack region
`memdiver-call-sys/src/linux.rs:687-722`, `memdiver-call-sys/src/wine32.rs:758-793`

`ensure_frame` looks up the region containing `layout.frame`, which is roughly 144–160 bytes
below the interrupted RSP (below the 128-byte red zone, plus alignment and stack arguments).
If the current stack mapping is that
close to its own base and a *different* writable mapping sits immediately below it, the
frame lands in that other mapping; the checks (writable, `frame - region.base >= 4096`,
`end <= region.end`) can all pass, and the return address/arguments are written into
unrelated memory. The callee's stack then grows down through that mapping.

**Fix:** require the frame region to be the region that contains the interrupted stack
pointer (`region.contains(Address::new(saved_rsp))`), or at least require
`layout.frame >= region.base && saved_rsp <= region.end`. A guard gap usually makes
`region_at` return `None`, but the adjacent-mapping case is real for custom stacks, thread
stacks packed against heap mappings, and newly grown stacks.

#### 3b. Native Linux has no `function == saved.rip` guard (silent false success)
`memdiver-call-sys/src/linux.rs:242-279` (compare `wine32.rs:467-478`)

The Linux backend arms the return breakpoint at `saved.rip` and then redirects `RIP` to
`function`. If `function == saved.rip` — plausible when the caller targets the routine the
interrupted thread is currently executing, e.g. a `tick`/`update` function in a spin loop —
the hardware breakpoint fires immediately on resume, before the function runs.
`is_breakpoint_hit` sees `rip == breakpoint` and the `DR6` hit bit and accepts it,
so `execute` returns `saved.rax` as the call result and the function is never invoked. The
target is resumed correctly afterwards (the restore puts `RSP`/`RIP` back), so this is a
silent wrong-result bug rather than corruption — but it is exactly the case the Wine32
backend rejects with `InvalidArgument { index: 0, reason: "the function address equals the
return address" }`. Mirror that guard in the native Linux path (or reject earlier in the safe
crate's native validation).

This was **reproduced** in this review: with a fixture spinning on `fixture_add(2, 3)` and
4000 calls to `fixture_add(40, 2)`, 916 calls returned `0x5` (the spin loop's previous
return) instead of 42, with no error. See the appendix.

#### 4. `Error::Cleanup.call` is used for non-call failures
`memdiver-call/src/caller.rs:846-886`, `memdiver-call/src/error.rs:175-187,244-260`

`close_after` (Windows `open`) and `detach_after` (Linux `open`/`new`) put the *primary
open failure* into `Error::Cleanup { call: Some(...) }`:

```
failed to restore the target state: PTRACE_DETACH failed: ... (the call also failed: failed to open memdiver::Process::open for process 7: ...)
```

Nothing was called. This contradicts the field's documented meaning ("The call failure, when
the call also failed"), the variant description, and the README's "Error::Cleanup keeps the
call failure in `call`". It also prints the function/pid context twice when both are present.

**Fix:** rename the concept to `cause`/`primary` (or add a separate `OpenCleanup` variant),
and make `Display` say "additionally"/"during setup" rather than "the call also failed".
`Error::Cleanup.function` is also redundant when `call` already carries `function`.

#### 4b. A failed `CloseHandle` can mask the Windows leak report
`memdiver-call-sys/src/windows.rs:314-337`, `memdiver-call-sys/src/lib.rs:84-98`

On the "wait failed, the thread may still run" path, `cleanup` records `close_handle(thread)`
first and only then `record_error(Leak)`. `Failures` keeps the first error, so if
`CloseHandle` fails the caller receives `Platform(CloseHandle)` and never learns that the
stub and result pages were deliberately abandoned. That contradicts the `cleanup` doc and the
`Error::Leaked` contract. Record the leak first (or keep both, preferring `Leak` and
attaching the close failure) so an abandoned allocation is always visible.

#### 5. Return values narrower than 64 bits are passed through raw
`memdiver-call/src/lib.rs:27-28`, `memdiver-call-sys/src/linux.rs:279`, `memdiver-call-sys/src/stub.rs:88,167-175`

The result is read as full `RAX` (x86_64) or `EDX:EAX` (x86) and returned as `u64`.

* On x86_64, the upper 32 bits of `RAX` are **undefined** for a function returning `int`,
  `bool`, `HRESULT`, etc.
* On x86, `EDX` is caller-saved scratch for any return type narrower than 64 bits, so a
  `BOOL` that returns false can come back as `0x????????00000000`; `result == 0` then fails.

The README's "Return values on Windows `x86`" section does warn to use the low half, but the
rustdoc has no equivalent caveat for native Windows `x86` (it only mentions `EDX:EAX` in the
Wine section), and x86_64 has no caveat at all. The fixture never returns a 32-bit value on a
32-bit target, so CI cannot catch this.

**Fix:** add an explicit return-width choice (analogous to `with_wide_arguments`), or
document "cast to the declared return type before comparing". Zero-extending by default is
not an option on x86 because a real 64-bit return uses `EDX:EAX`. Also add a fixture function
returning `BOOL`/`u32` on x86 to lock the behavior in.

### P2 — Error model, documentation accuracy, panic safety

#### 6. `CallStatus` in the sys crate is exhaustive while the safe one is not
`memdiver-call-sys/src/error.rs:25-42`, `memdiver-call/src/error.rs:43-64,284-292`

`memdiver_call_sys::CallStatus` lacks `#[non_exhaustive]` although the safe `CallStatus` has
it and even defines `Other` for unknown platform statuses. Adding a sys variant is therefore
a semver-breaking change for the published `memdiver-call-sys`, and the safe mapping has no
wildcard arm despite `Other` existing. Mark the sys enum `#[non_exhaustive]` and map the
wildcard to `CallStatus::Other` (or remove `Other`).

#### 7. Documented error sets are incomplete/inaccurate
`memdiver-call/src/caller.rs:74-96,166-176`, `memdiver-call/src/lib.rs:23-36`

* `call` can return `Error::Open` (per-call `PTRACE_SEIZE`/`CreateRemoteThread` resource
  failures) and `Error::Platform`/`Error::Memory` (region inspection), none of which are
  listed.
* `open`/`new` can return `Error::Memory` from `check_bitness` (`Process::pointer_width`
  failure), not listed.
* `new_wine` can return `Error::Memory` from `detect`, not listed.
* The type docs at `caller.rs:44-47` say a second attach "fails with `EBUSY`". I reproduced
  this on Linux 7.3.3: `PTRACE_SEIZE` on an already-traced target returns **`EPERM`** (errno
  1), reported as `Error::Open { operation: "PTRACE_SEIZE" }`. The README hedges
  "`EPERM`/`EBUSY`"; the type docs should too, and should name the `Error::Open` shape.
* `call`'s Errors section claims "All validation errors are returned before the target is
  touched", but `RemoteCaller::call` calls `process.is_alive()` *before* `validate`
  (`caller.rs:184-188`); a dead target therefore reports `TargetExited` even for an invalid
  address. Reorder or reword.

#### 8. Safe-point timeout is not a hard bound; the wait loop can spin and block
`memdiver-call-sys/src/wine32.rs:600-639,649-678,716-740`

There are three distinct problems in the timeout path:

* `wait_for_safe_point` checks the deadline only when `waitpid(WNOHANG)` returns 0. Every
  reaped stop is handled and resumed without looking at the clock, and there is no stop
  counter. A job-control-stopped target re-delivers `SIGSTOP` on every `PTRACE_CONT`, so the
  loop can spin forever and the documented `with_safe_point_timeout` never fires; the same
  applies to any target that stops in a tight cycle.
* After `TimedOut`, the code sends `PTRACE_INTERRUPT` and blocks in `wait_for_initial_stop`
  with no timeout. A tracee in uninterruptible sleep can therefore exceed the bound
  arbitrarily.
* `fail_after_wait`'s `interrupt_and_stop` has the same property, and when the tracee is
  already stopped, `PTRACE_INTERRUPT` queues a trap that is only reported after a
  `PTRACE_CONT`, which the code never issues — a hang instead of a prompt return.

**Fix:** check `Instant::now() >= deadline` at the top of every iteration (not only when
`waitpid` returns 0), cap forwarded stops as `wait_for_breakpoint` does, and after an
interrupt poll with `WNOHANG` against a short grace deadline. Track stopped-vs-running
explicitly so `PTRACE_INTERRUPT` is only sent to a running tracee. At minimum, document that
the bound is best-effort.

`Instant::now().checked_add(timeout)` returning `None` for an enormous timeout also silently
disables the deadline (`wine32.rs:606`); reject or clamp the value.

#### 8b. `PTRACE_DETACH`'s `ESRCH` is treated as "target gone", but it also means "not stopped"
`memdiver-call-sys/src/linux.rs:417-423`, reachable from `linux.rs:129-139` and
`wine32.rs:716-733`

`ptrace_detach` checks that the tracee is stopped and returns `ESRCH` when it is running (not
only when it is dead). `detach` maps every `ESRCH` to `Ok`, so a cleanup that could not stop
the tracee reports success and leaves it seized — possibly with the safe-point/return
breakpoint armed, which will freeze the target at the next hit with no tracer waiting for the
stop. This is most relevant to `wine32::fail_after_wait`'s last-resort path and to `attach`'s
interrupt-failure paths.

**Fix:** distinguish "the task exists but is running" from "the task is gone" (check
`/proc/<tid>`/`waitpid`), interrupt and wait for a stop before detaching, and return an error
if the tracee cannot be detached.

#### 9. Linux/Wine guards are not panic-safe during `call`
`memdiver-call-sys/src/linux.rs:78-81`, `memdiver-call-sys/src/wine32.rs:116-119`

`Attached::call(mut self, ...)` sets `self.armed = false` *before* running the call. If
anything in `run` panics (allocation abort aside, any future panic), the guard's `Drop` no
longer detaches, leaving the tracee stopped with the debug registers armed. The Windows
`RemoteState` has explicit panic-safe `Drop`; the Linux guards should too:

```rust
pub fn call(mut self, ...) -> CallOutcome {
    let outcome = run(...);   // run already restores + detaches on its normal paths
    self.armed = false;
    outcome
}
```

This also matches the guard type's documented "dropping it without calling ... detaches".

#### 10. `Attached::call` and `CallOutcome` should be `#[must_use]`
`memdiver-call-sys/src/linux.rs:78`, `memdiver-call-sys/src/wine32.rs:116`, `error.rs:12-23`

Ignoring a `CallOutcome` silently discards a call/cleanup failure. Clippy's pedantic
`must_use_candidate` flags both `call` methods. Add `#[must_use]` to `CallOutcome` and/or the
methods.

#### 11. `windows::call` is a safe function with unchecked preconditions
`memdiver-call-sys/src/windows.rs:115-132`

The doc says "The caller must have validated the address, the argument count, and the ABI",
yet the function is safe and will happily jump to an arbitrary remote address. If the sys
crate is a published "unsafe platform mechanism", these entry points should be `unsafe fn`
with `# Safety` sections (clippy's `missing_safety_doc` then enforces it), or should validate
the address themselves. The Linux/Wine `Attached::call` methods do validate internally, so
the trust boundary currently differs by backend. Marking the risky entry points `unsafe`
also communicates the risk that the safe crate deliberately takes on.

#### 12. Wine32 reuses pre-safe-point debug state for the return breakpoint and for restore
`memdiver-call-sys/src/wine32.rs:340-357,480-498,583`

The thread runs freely from the initial stop to the safe point. FP state is re-read at the
safe point, but the debug-register state is not: the return-breakpoint slot is chosen from
the *pre-wait* `DR7`, and `restore_and_detach` restores the pre-wait `DR0–DR3/DR6/DR7`. Any
hardware breakpoints the target itself installed during the wait are overwritten when the
slot is re-armed and are then lost on restore. This is likely unavoidable without a richer
protocol, but it is a visible side effect that the "debug-register scope" documentation does
not mention; at minimum document it, or re-read DR state right after the safe-point hit and
merge/restore it carefully.

#### 13. Undocumented mechanism limitations
`memdiver-call/src/lib.rs:110-119`, `memdiver-call/README.md:227-261`

Several hazards that follow directly from the mechanism are not in the public limitations:

* **Stack headroom**: the frame is placed below the interrupted RSP, and the code only
  guarantees 4 KiB of mapped stack below it (`STACK_HEADROOM`). A callee with a large stack
  frame or deep recursion can hit the guard page and crash the target. The internal comment
  says "a guard band, not a proof"; the public docs do not.
* **Unwinding**: the synthetic return address is the interrupted instruction, not a real
  call site and has no unwind metadata. C++ exceptions, `longjmp`, or a `backtrace` that
  unwinds past the called function are invalid on **native Linux** too (the docs only say
  this in the Wine section).
* **False early return**: the return breakpoint is set at the interrupted RIP / safe point,
  so if the called function itself (re)enters that address, the breakpoint fires early and
  the call is reported as returned with whatever `RAX`/`EDX:EAX` held. This is rare but
  inherent to the hardware-breakpoint design and worth one sentence.
* **Signal at the initial stop**: `wait_for_initial_stop` accepts any `WIFSTOPPED` stop,
  not specifically the `PTRACE_INTERRUPT`/`PTRACE_EVENT_STOP` stop (`linux.rs:283-303`); a
  signal-delivery stop that wins the race is then resumed with signal 0 in `execute`, i.e.
  the signal is swallowed. Likewise, a group-stop is not distinguished. Verify the event
  (`status >> 16`) and forward the signal.
* **Signal/stop classification in `wait_for_breakpoint`** (`linux.rs:330-340`): any stop
  whose `WSTOPSIG` is `SIGTRAP` but which `is_breakpoint_hit` does not recognize is forwarded
  as a real `SIGTRAP` (`resume(tid, SIGTRAP)`), whose default action terminates the target.
  A group-stop (`SIGSTOP`/`SIGTSTP`) is re-delivered and re-stops until `MAX_SIGNAL_STOPS`,
  then the call fails with the target still group-stopped. Classify signal-delivery stops
  versus group/event stops (`PTRACE_GETSIGINFO`/`status >> 16`), suppress or `PTRACE_LISTEN`
  group-stops, and do not forward `SIGTRAP` blindly.
* **Signal suppressed when the call gives up** (`linux.rs:336-340,416-423`): after
  `MAX_SIGNAL_STOPS` the tracee is parked at a signal-delivery stop; `restore_and_detach`
  uses `PTRACE_DETACH` with signal 0, discarding the pending signal (e.g. `SIGSEGV`/
  `SIGTERM`) instead of delivering it. Pass the last stop signal to the detach (or re-raise
  it) and surface it.

#### 14. Windows execution handle requests unnecessary rights
`memdiver-call-sys/src/windows.rs:96-113`, `memdiver-call/README.md:195-208`

The execution handle is used for `VirtualAllocEx`, `VirtualProtectEx`,
`FlushInstructionCache`, `CreateRemoteThread`, `VirtualFreeEx` and `CloseHandle`. Microsoft
documents `CreateRemoteThread` as requiring `PROCESS_CREATE_THREAD`,
`PROCESS_QUERY_INFORMATION`, `PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE` and
`PROCESS_VM_READ`, so five of the six requested rights are justified by that call alone;
only `PROCESS_SYNCHRONIZE` on the *process* handle is not needed (the wait and exit-code
calls use the thread handle). **This finding was corrected after review**: the earlier claim
that only `PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION` are required was wrong. The mask
was left unchanged; dropping `PROCESS_SYNCHRONIZE` is optional. (The agent brief specified
the six-right mask as well.)

#### 15. CFG/IBT reasoning does not cover the stub entry
`memdiver-call-sys/src/windows.rs:239-267`, `memdiver-call/README.md:234-239`

The direct `call rel32` avoids CFG/IBT *inside* the stub, but the stub entry itself is the
thread start routine and is reached by an indirect branch from the Windows thread trampoline;
it does not start with `ENDBR64`. Windows IBT enforcement is not enabled by default today,
so this is forward-looking, but the README's claim that the direct call keeps "CET-IBT out
of the picture" is too strong. Adding `ENDBR64` (a no-op on non-CET CPUs) to the stub prefix
is cheap; alternatively narrow the documentation. The indirect fallback has the mirror
requirement: the callee must start with `ENDBR64` on an IBT-enforcing system.

#### 15b. x64 stub leaves `AL` undefined for variadic callees
`memdiver-call-sys/src/stub.rs:63-66,82-84`

The Microsoft x64 ABI requires `AL` to hold the number of vector registers used when calling
a variadic function. The stub leaves `AL` = the low byte of argument 5 (direct `call rel32`)
or of the function address (indirect `call rax`). The safe crate documents variadic calls as
unsupported, but the sys crate's `call` does not, and a variadic callee (a log/assert
function) would read a bogus XMM count and spill 1–4 XMM registers into the shadow space.
Emitting `xor eax, eax` immediately before the call (and using `r11` for the indirect target
so `RAX` can be zeroed) is cheap and makes the ABI assumption explicit.

### P2 — Duplication and modularity

#### 16. Three public ABI enums and three mapping functions for one concept
`memdiver-call/src/options.rs:16-31`, `memdiver-call-sys/src/windows.rs:37-50`,
`memdiver-call-sys/src/wine32.rs:50-61`, `memdiver-call/src/caller.rs:644-664`,
`memdiver-call-sys/src/windows.rs:500-508`, `memdiver-call-sys/src/wine32.rs:251-258`

`CallAbi`, `windows::Abi` and `wine32::WineAbi` are the same four conventions (plus `Auto`),
each with a hand-written 1:1 mapping. Put one `Abi` in the sys crate (with `Auto`) and one
`From<CallAbi>` (or a single `caller` mapping) so adding a convention touches one place.
The current shape also makes the sys crate's API needlessly platform-shaped: `Abi` is only
exported on Windows, `WineAbi` only from the `wine32` module, and both duplicate the x86
layout mapping.

#### 17. Duplicated validation between the safe crate and the sys crate
`memdiver-call/src/caller.rs:236-363,687-705` vs `memdiver-call-sys/src/windows.rs:359-424`,
`memdiver-call-sys/src/wine32.rs:283-338`, `memdiver-call-sys/src/x86_args.rs:58-108`

The same policies are implemented twice: max-argument count (`MAX_ARGUMENTS` is defined in
both crates), wide-index range/duplicate checks (`wide_flags` in the safe crate;
`X86Error::Index`/`Duplicate` in the sys crate), address range checks, executable-region
checks, thread==PID checks, and safe-point range/equality checks. `memdiver-call-sys`'s
README and crate docs say "It deliberately contains no policy", but it contains a
substantial amount of it. Two copies mean drift (a safe-crate rule change must be mirrored)
and the redundant region lookups are the performance bug in finding 1.

**Fix:** choose one policy owner. Keep the sys crate's *mechanism invariants* (e.g., "the
frame must fit its region", "the x86 slot encoding has at most 12 dwords") and let the safe
crate own argument/ABI/address policy, passing a validated request. If the sys crate is
public and must defend itself, keep its checks but have it accept the safe crate's
`RegionMap` so they are cheap.

#### 18. Copy-pasted helpers
| Duplicate | Locations |
|---|---|
| `ensure_frame` (35 lines, identical) | `linux.rs:687-722`, `wine32.rs:758-793` |
| `map_x86_error` (identical) | `windows.rs:477-497`, `wine32.rs:260-280` |
| `inspect` (identical) | `linux.rs:729-735`, `windows.rs:560-566` |
| ABI→`X86Abi` mapping | `windows.rs:500-508`, `wine32.rs:251-258` |
| attach/SEIZE/INTERRUPT/wait + guard/detach | `linux.rs:114-140` + `wine32.rs:149-173`, `linux.rs:95-101` + `wine32.rs:133-139` |
| `detach_after` / `detach_wine32_after` (bodies identical) | `caller.rs:858-886` |
| `STACK_HEADROOM` const | `frame.rs:15`, `frame_x86.rs:11` |
| `MAX_ARGUMENTS` | `caller.rs:13`, `memdiver-call-sys/src/lib.rs:57` |
| fixture locator | `tests/common/mod.rs:155-167`, `examples/call_fixture.rs:43-58` |

`wine32::Attached` can simply wrap `linux::Attached` (expose the `tid` with a `pub(crate)`
getter) to remove the duplicated attach/detach/Drop logic; `wine32::ensure_frame` can call a
shared `frame::validate` helper; `map_x86_error` belongs next to `X86Error`; and
`detach_wine32_after` disappears if `wine32::Attached` is the same type.

#### 19. Platform orchestration in `caller.rs` repeats the same shapes
`memdiver-call/src/caller.rs:394-550,552-664,844-886`

There are two `open_pinned` functions, two `adopt` functions, two `call_pinned`, two
near-identical cleanup wrappers, and four struct literals that build the same `RemoteCaller`
(with one optional `execution` field). A small `enum Backend { Native, Wine32 }` plus
`fn assemble(process, kind)` / `fn finish_attach(...)` would shrink this file substantially
and make the cfg split easier to audit. The file is 1040 lines; most of it is mapping and
platform plumbing.

### P2 — Readability and idioms

#### 20. `wine32::run` is a ~300-line function with 14 copies of the same error-return block
`memdiver-call-sys/src/wine32.rs:283-588`

`run` has 18 `return CallOutcome { ... }` sites; 14 are exactly
`CallOutcome { result: Err(error), cleanup: linux::detach(tid).err() }`. Clippy's pedantic
`too_many_lines` reports 286/100.

Introduce

```rust
fn fail_detached(tid: libc::pid_t, error: SysError) -> CallOutcome {
    CallOutcome { result: Err(error), cleanup: linux::detach(tid).err() }
}
```

and use `let ... else { return fail_detached(tid, error) }` for the register/FP/debug/
executable checks. That removes roughly 70 lines and makes the happy path visible. The
`base`/`fp`/`debug` state machine then reads as a sequence of guarded steps instead of nested
matches. The same pattern (smaller) exists in `linux::run`/`execute`.

#### 21. Dead defensive checks in the frame layouts
`memdiver-call-sys/src/frame.rs:43-49`, `memdiver-call-sys/src/frame_x86.rs:31-36`

The `end > saved_rsp (- RED_ZONE)` and `frame % 16 != 8` checks are mathematically
unreachable given the preceding arithmetic (the tests can never exercise them, and the
`None` return claims a failure mode that cannot occur). Prefer `debug_assert!` with the
reason, or remove them and document the invariant once. The "limit itself is two words below
the red zone so the 16-byte-down rounding has room" comment does not describe what the code
actually computes (the frame lands 24 bytes below the red zone for 0 args); reword it.

#### 22. Error conversion chain is hard to follow
`memdiver-call/src/caller.rs:764-832`

`map_open`, `map_wine_error`, `map_call_error` and `map_cleanup_error` each match most
`SysError` variants, and two of them fall back into `map_call_error(other, Address::NULL,
pid)`. As a result the same `SysError` can become `Open`, `Platform`, or `CallFailed`
depending on the caller. That is intentional (context matters), but it deserves a table in
the docs and, ideally, a single `fn map(error, context) -> Error` with a context enum
(`Open`, `Call`, `Cleanup`) so the rules are visible in one place. `Error::Open`'s source is
a `Box<dyn Error>` while `Error::Platform` carries `PlatformError` directly; callers must
`downcast_ref` the former (the unit test does exactly that) to read the raw code. Consider
carrying `PlatformError` in both, with the memdiver error as an extra source field.

#### 23. Cast/`unwrap_or` idioms hide impossible failures
`memdiver-call-sys/src/linux.rs:231,402,427,526,537,559`,
`memdiver-call-sys/src/windows.rs:78,539`, `memdiver-call-sys/src/wine32.rs:520`

Examples: `usize::try_from(layout.end - layout.frame).unwrap_or(8)`,
`usize::try_from(signal).unwrap_or(0)`, `u8::try_from(index).unwrap_or(0)`,
`usize::try_from(info.dwPageSize).unwrap_or(4096)`, `self.handle.unwrap_or(0)`. Each is
either provably infallible (so `as` with a comment or a `debug_assert` is clearer) or would
silently produce a wrong value. `Execute::raw()` returning 0 after `close()` is unreachable
because `close` consumes `self`; `Option` plus a private `handle()` would say that.

#### 24. Minor idiom nits
* `memdiver-call-sys/src/lib.rs:79-114`: `Failures::record` nests `if`s; implement it as
  `record_error(result.err())` and drop `record_error` (or make both one function).
* `memdiver-call-sys/src/linux.rs:586-596`: nested `if let Some(code) = ... { if code != 0 }`
  → `if let Some(code) = error.raw_os_error().filter(|&code| code != 0)`.
* `memdiver-call-sys/src/windows.rs:245-249`: `Some(unsafe { transmute(...) })` — the inner
  `unsafe` is redundant inside an already-unsafe block; reorder the comment.
* `memdiver-call-sys/src/windows.rs:511-530`: `read_result`'s manual `copy_from_slice` into
  two arrays can be `u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes"))` or
  `Process::read_value::<[u64; 2]>` (which the brief suggests).
* `memdiver-call-sys/src/windows.rs:241-244`: the `SAFETY:` text in `create_thread` describes
  the *x86* thread-entry contract ("`stdcall` ... `ret 4`") but the function is compiled on
  x64 too, where the entry is Microsoft x64, the stub ends with a plain `ret`, and
  `extern "system"` is not `stdcall`. Split the justification per architecture.
* `memdiver-call-sys/src/stub.rs:15-22`: `direct_call` exists only for unit tests; either
  gate it to `#[cfg(test)]` or assert on bytes in tests.
* `memdiver-call-sys/src/stub.rs:124-141`: the x86 stub relies on `debug_assert!` for the
  imm8 bounds; `windows::call_inner` enforces ≤ 6 args in release, but the stub builder
  itself should return an error or use imm32 encodings if it is ever reachable with more.
* `memdiver-call-sys/src/x86_args.rs:59-80`: three heap allocations per x86 call
  (`is_wide`, `arguments`, `stack`). With six arguments, `[bool; 6]`/`[u32; 12]` + length
  avoids all of them.
* `memdiver-call/src/caller.rs:687-705`: `wide_flags` allocates a `Vec` on every call even
  when `wide_arguments` is empty; a `u8` bitmask (max 6 args) is enough.
* `memdiver-call-sys/src/windows.rs:128,532-540`: `page_size()` calls `GetSystemInfo` on
  every call; the page size is constant per host — cache it with `OnceLock` (or compute in
  `RemoteCaller`).
* `memdiver-call-sys/src/wine32.rs:47,649-678`: the safe-point poll sleeps 200 µs between
  `waitpid(WNOHANG)` calls; a blocking wait in a helper thread (or increasing backoff) would
  remove most wakeups.
* `memdiver-call-sys/src/linux.rs:471-500`: `get_fp_state` heap-allocates a 4 KiB box per
  call; a stack `AlignedBuffer` or a reusable buffer would remove it.
* `memdiver-call-sys/src/linux.rs:567-598,547-550`: `ptrace_raw` does not clear `errno`
  before the request and infers failure from `result == -1` plus a possibly stale `errno`.
  `PTRACE_PEEKUSER` legitimately returns `-1` for an all-ones word, so a stale `errno` turns
  valid data into an error (an all-ones `DR7` would make `free_slot` report all four slots
  busy). Clear `errno` before each `ptrace` and treat `-1` as success only when `errno` is
  still 0, or read the debug registers through `PTRACE_GETREGSET`/another path.
* `memdiver-call-sys/src/linux.rs:78-81,95-101`: the `Attached` guard's `Drop` only detaches;
  if a panic ever happens after the breakpoint is armed, the detach leaves `DR7` armed and
  the target traps into a stop nobody waits for. Keeping the guard armed until `run` returns
  (finding 9) plus restoring the debug state in `Drop` would make the documented "best-effort
  detach on drop" actually safe.

### P3 — Tests, CI, packaging, repository

#### 25. Test coverage gaps worth closing
The end-to-end suites are strong; the following behaviors are documented but untested:

* `CallStatus::NoCompletion`: a Windows fixture function that calls `ExitThread(0)` (the
  completion-flag path) is not exercised.
* Two `RemoteCaller`s competing for one target (the documented "already traced" error) is
  not tested; a direct `PTRACE_SEIZE` before `open` would make a deterministic test, as my
  probe showed (`Error::Open { operation: "PTRACE_SEIZE", source: code 1 }`).
* Signal forwarding / `MAX_SIGNAL_STOPS` during `wait_for_breakpoint` is untested (the
  fixture could install a handler and a test could send signals while a call is blocked).
* The stale-DR6-before-arm asymmetry (see below) is untested; my probe on this kernel did
  not reproduce `EIO`, so a regression test may not be portable.
* `wine32::detect`'s PE parser is only testable through a live Wine process; factor the
  DOS/PE header parsing into a pure function and unit-test 32-bit, 64-bit, invalid
  `e_lfanew`, and truncated headers.
* The x64 indirect-call fallback is byte-tested but never executed end-to-end.
* `Error::Poisoned`, `Error::Leaked`, and the cleanup-failure `Display` paths have no
  integration coverage.
* `open`/`new` on a dead PID (the `check_shadow_stack` → `TargetExited` path) is untested.

#### 26. CI
`.github/workflows/ci.yml`

* Use `--locked` on the test/clippy/check commands so CI validates the committed
  `Cargo.lock` instead of silently resolving a different dependency set.
* The MSRV job (`cargo check` on 1.85) depends on the locked dependency versions; adding
  `--locked` makes that explicit.
* Consider `cargo test --release` on Linux (cheap, and it changes `debug_assert!` behavior).
* The Wine jobs create prefixes in the workspace without a cache key; fine, but the
  `windows-wine` job does not use `Swatinem/rust-cache` at all, so every run recompiles.
* The Wine32 suite runs with `--test-threads=1`, which is belt-and-braces given the
  `SERIAL` mutex; leave it, but note the mutex already enforces exclusivity.

#### 27. Test-harness nits
`memdiver-call-tests/tests/common/mod.rs`, `tests/wine32.rs`, `examples/call_fixture.rs`

* `Fixture.data` is never read (masked by `#![allow(dead_code)]`).
* `fixture_path` is duplicated between `common/mod.rs` and the example (the example also
  tries `..`/`../..`); `common` falls back to `CARGO_BIN_EXE_*` without checking it exists,
  so a missing fixture becomes an exec error rather than the clear assertion in the Wine
  suite.
* `find_pe_process` parses `/proc/<pid>/stat` with `split_whitespace().nth(3)`; `comm` can
  contain spaces and parentheses, which shifts the fields. Split at the last `)` instead.
* `wine32.rs` writes `libc::kill`/`ptrace` code inline; adding `SAFETY` comments there is
  good, but the blocking `waitpid` after `SIGKILL` can hang the test process if the child is
  unkillable (D state); a bounded wait would make the harness more robust.

#### 28. Public API and packaging polish
* **Re-export the `memdiver` types that appear in the public API**
  (`pub use memdiver::{Address, Process};`). Today every user must add `memdiver` as a
  direct dependency just to name `Address`/`Process`, and must keep its version aligned
  with `memdiver-call`'s transitive version. A facade re-export is the standard fix.
* `memdiver-call-sys` exposes `WineTarget`/`detect` (whose value the safe crate discards),
  `is_supported()` (always true wherever the crate compiles), and a public `wine32` module
  with a second `Attached`/`Abi` API. Either use `WineTarget::module_base` in
  `RemoteCaller` (e.g., expose the PE base for callers) or remove it; `is_supported` can go.
* `memdiver-call-sys::CallSpec` has public fields and no `#[non_exhaustive]`; adding a field
  is semver-breaking for a published crate.
* `memdiver-call/Cargo.toml`: add `repository` (crates.io shows a home-page gap); consider
  bumping `windows-sys` from 0.59 (2024) to a current 0.6x before the next release; note
  that `memdiver-call` is 0.1.1 while the workspace and `-sys` are 0.1.0, which is fine but
  should be intentional in the release notes.
* The root `remote-call-investigation.md` and `remote-call-agent-prompt.md` (≈77 KiB of
  internal design briefs) are tracked but unreferenced from the README. They are useful
  history; move them under `docs/` (or drop them from the published tree) so the root reads
  as a library, not a work log.
* `.gitignore`'s `debug` pattern ignores any file/directory named `debug` at any depth; a
  `src/debug.rs` is fine (extension), but a future `debug/` module would silently vanish.
  Prefer `/target/debug`.
* `CHANGELOG.md` (0.1.0) does not mention `TargetKind`/`target_kind` or
  `CallOptions::with_safe_point_timeout`'s default; minor completeness.

#### 29. Documentation accuracy sweep
* `memdiver-call-sys/src/lib.rs:1-22` says "It has no policy", contradicted by the
  validation described in finding 17; align the sentence with reality.
* `memdiver-call-sys/src/lib.rs:14-18` and the sys README describe only Linux/Windows, not
  the `wine32` backend that the same crate implements.
* `memdiver-call/src/lib.rs:23-36` says "Cross-bitness and WOW64 return `Error::Unsupported`"
  in the supported matrix, then documents the cross-bitness Wine mode below; qualify the
  matrix bullet with "for native targets".
* `memdiver-call/src/error.rs:107-110` (`ReadOnly`) and the README recommend
  `memdiver::Process::open`; if the facade re-export is added, point at
  `memdiver_call::Process`.
* `PlatformError` prints only "operating-system error N"; an optional
  `std::io::Error::from_raw_os_error(code)` message would make logs actionable (and on
  Windows, `FormatMessage`) without changing the numeric code contract.
* `memdiver-call/src/lib.rs:110-119`: "No timeout ... A call that never returns hangs the
  caller" is good; add "the safe-point wait is not a hard bound" if finding 8 is not fixed.
* The type docs' `EBUSY` claim (finding 7) and the README's `EPERM`/`EBUSY` hedge should be
  reconciled with the observed `EPERM`.
* The `DR6`-before-`DR7` rationale (`linux.rs:385-389`, `wine32.rs:681-683`, and the
  investigation doc) is not supported by the current x86 ptrace implementation: the kernel
  does not validate `DR6` when writing `DR7`, and my stale-`DR6` probe on Linux 7.3.3 did
  not reproduce the `EIO`. Keep the write if it is harmless, but correct the rationale (and
  the asymmetry between the two backends).
* The xstate constant's "Maximum size" comment is wrong (finding 2).
* `memdiver-call-sys/src/windows.rs:115-119`: the `call` doc says it "frees every allocation
  it created", but the deliberate leak path in `cleanup` does not; reword to "frees every
  allocation unless it cannot prove the remote thread has stopped, in which case it reports
  `SysError::Leak`".
* `memdiver-call-sys/src/error.rs:157-161`/`Leak` wording "Remote memory was intentionally
  abandoned" is fine, but the safe `Error::Leaked` Display "abandoned remote memory because
  {operation} was unsafe: {reason}" reads oddly; consider "skipped {operation} because
  {reason}".

---

## What is good

* **Layering intent is clear and mostly enforced**: `#![forbid(unsafe_code)]` in the safe
  crate; all FFI in the sys crate; no `memdiver` forks or patches.
* **Cleanup discipline**: every sys path funnels through `restore_and_detach` /
  `RemoteState::cleanup`; the `CallOutcome` split (result vs cleanup) is a good design, and
  the safe crate never reports `Ok` after a cleanup failure.
* **Unsafe code is small and documented**: five unsafe sites in `linux.rs`, nine in
  `windows.rs`, one in `wine32.rs`, each with a precise `SAFETY:` comment; the ptrace
  wrapper centralizes the variadic ABI.
* **The tricky mechanisms are correct in the normal paths**: red-zone-safe SysV frame,
  16-byte alignment at call sites on both ABIs, shadow space and stack-argument positions,
  `EDX:EAX` capture, `ret 4` for the x86 stdcall thread entry, `orig_rax = -1`, DF/TF
  clearing, W^X, and the result/flag separation.
* **Tests actually exercise the risky paths**: blocked-in-`read(2)` Linux target, target
  exit during a call, concurrent serialization, Wine safe points/timeout, wide 64-bit stack
  arguments on x86, and byte-exact stub tests on every host. Running them under Wine and on
  the native Linux path is more than most projects do.
* **Docs are unusually thorough**: the feature matrix, Wine setup, Yama/subreaper notes,
  CFG/CET caveats, observability, and ethics sections are all above average.

## Independent audit cross-check

A second, independent review of the Windows backend reconstructed both stubs from `stub.rs`
and disassembled them with `objdump` (i386 and x86-64), and validated the Win64 stack-argument
placement against `x86_64-w64-mingw32-gcc` output. It found **no defect** in the stub encodings
(REX/modrm/sib/disp8, `moffs64`, `imm32` sign-extension, `ret 4`), shadow space, 16-byte
call-site alignment, x86 wide-argument order, `thiscall`/`fastcall` register placement,
nonvolatile-register preservation, result-before-completion ordering, or the "never free while
the thread may run" condition. It added findings 4b and 15b (and the `SAFETY:`/`call`-doc nits
in 24/29) and independently reached finding 5's x86 `EDX` case.

One audit claim was checked and **rejected**: that `open` can pair an execution handle with a
memory handle for different process instances after PID reuse. On Windows the PID is a property
of the process object and is not reused while any handle keeps the object alive
([Microsoft, "When does a process ID become available for reuse?"](https://devblogs.microsoft.com/oldnewthing/20110107-00/?p=11803));
on Linux the `PTRACE_SEIZE` happens *before* `Process::open` and pins the task. The pinning
protocol as documented is sound.

A second independent pass over the Linux/Wine backends (checked against the upstream ptrace,
regset and xstate code) added the practical xstate failure mode now in finding 2, the missing
`function == saved.rip` guard (3b), the deadline/stop-classification problems in 8 and 13, the
`PTRACE_DETACH`/`ESRCH` conflation (8b), and the `errno`/guard nits in 24. It found **no
defect** in the `struct user` debug-register offsets (it recompiled `offset_of!` against the
same `libc`), the SysV frame arithmetic/red zone, the Windows x86 frame alignment, or the
`saved`/`orig_rax = -1` round trip. The DR6-before-DR7 claim did not survive its kernel-source
check or my probe either, so it is now a documentation nit rather than a bug.

## Suggested remediation order

1. **Region-map snapshot per call** (finding 1) — biggest measurable win, low risk.
2. **xstate sizing** (finding 2) — on AMX-class CPUs the current code cannot restore FP state
   at all.
3. **`function == saved.rip` guard** (finding 3b) — silent wrong results; mirror the Wine32
   guard.
4. **Frame-in-stack-region check** (finding 3) — cheap hardening.
5. **Timeout/stop handling** (findings 8, 8b, 13) — the safe-point wait can hang and the
   detach path can lie.
6. **Narrow-return documentation/option** (finding 5) — the x86 `EDX` case is a real
   correctness footgun.
7. **Error-model/doc truth pass** (findings 4, 4b, 5, 6, 7, 13, 15b, 29) — low risk, high
   user value.
8. **Panic-safe guards** (finding 9) and **`#[must_use]`** (finding 10).
9. **Wine32 DR-state documentation** (finding 12).
10. **Dedup pass** (findings 16–20) — mechanical, best after the API decisions above.
11. **Tests/CI polish** (findings 25–28).

## Appendix — reproduction snippets

Per-call cost (temporary test, removed after measuring):

```text
debug:   5000 calls in 1.336 s   (267.2 µs/call)
release: 5000 calls in 0.483 s   ( 96.6 µs/call)
release region_at: 5000 lookups  ( 13.2 µs/lookup, 32 regions)
release is_alive:  5000 calls    (  1.5 µs/call)
```

Already-traced probe (temporary test, removed after measuring):

```text
open error: Open { pid: 121, operation: "PTRACE_SEIZE", source: PlatformError { code: 1 } }
display: failed to open PTRACE_SEIZE for process 121: operating-system error 1
```

Stale-DR6 probe: `PTRACE_POKEUSER(DR6=1)` followed by enabling `L0` in `DR7` succeeded on
Linux 7.3.3, so the DR6-before-arm asymmetry did not reproduce as a failure on this kernel;
it remains a consistency nit, not a confirmed bug.

`function == saved.rip` probe (temporary fixture spin mode and test, removed after measuring):

```text
spin loop calls fixture_add(2, 3); test calls fixture_add(40, 2) 4000 times
real=3084 false_success=916 errors=0
false success sample: 0x5   (the spin loop's previous return, not 42)
```

That is a ~23 % silent-wrong-result rate when calling the function the thread is executing,
and it is why finding 3b is listed as a P1.


---

## Resolution status

All findings were worked through in the commits after the review baseline. This section
records the disposition so the report can be read against the final tree.

| Finding | Disposition |
|---|---|
| 1 region snapshots | **Fixed.** One `RegionMap` per validation phase and per sys backend; the Wine post-safe-point frame check uses a fresh snapshot. Release call cost on the 32-region fixture dropped from 96.6 µs to 74.9 µs, and the frame check now requires the same region as the interrupted RSP. |
| 2 xstate | **Fixed.** `NT_X86_XSTATE` is probed once with a 64 KiB aligned buffer, the returned size is cached, and save/restore use exactly that size; `NT_PRFPREG` is used only for `EINVAL`/`EOPNOTSUPP`/`ENODEV`. |
| 3 frame region | **Fixed.** `ensure_frame` is shared and requires the frame's region to contain the interrupted stack pointer. |
| 3b early return | **Fixed more broadly than proposed.** Instead of rejecting `function == saved.rip`, a breakpoint hit is accepted only when RSP is above the synthetic frame; early hits are stepped over with `EFLAGS.RF`. The new spin-add test calls the function the thread is running 1000 times and requires the real result every time. |
| 4 `Cleanup.call` | **Fixed docs/Display without breaking the API.** The field now documents both call and setup failures, and `Display` says "the preceding operation also failed". The field name is retained. |
| 4b leak masking | **Fixed.** The `Leak` is recorded before the close attempt, so a `CloseHandle` failure cannot hide abandoned memory. |
| 5 narrow returns | **Fixed docs + test.** A `Return values` section covers both ABIs; the fixture returns `u32` and the test relies only on the low half. |
| 6 `CallStatus` | **Fixed.** The sys enum is `#[non_exhaustive]`; the safe mapper falls back to `Other`. |
| 7 error docs / EBUSY | **Fixed.** Error lists are complete, the observed `EPERM` is documented (with the `EBUSY` hedge), and the validation-order claim was reworded. |
| 8 timeout/stops | **Fixed.** The deadline is checked every iteration, forwarded stops are capped, the post-timeout interrupt wait is bounded by a 500 ms grace, `PTRACE_INTERRUPT` is not sent to a stopped tracee, and `fail_after_wait` restores GP/debug without touching FP state. |
| 8b detach ESRCH | **Fixed.** `detach_with_signal` distinguishes a dead task from a running one and retries after a pending stop; a target that cannot be detached is reported. |
| 9 panic guards | **Fixed.** The guard stays armed until `run` returns, stores the saved `DebugState`, and restores it before detaching on unwind. |
| 10 `must_use` | **Fixed.** `CallOutcome` is `#[must_use]`. |
| 11 sys preconditions | **Rejected with rationale.** Making `windows::call` `unsafe` would force either `unsafe` into the `#![forbid(unsafe_code)]` facade or an unsafe wrapper, defeating the layering. The sys entry points keep documented preconditions, matching `memdiver`'s safe-but-dangerous write API. |
| 12 Wine DR window | **Documented** in the crate docs and README. |
| 13 limitations/signals | **Fixed/documented.** Stack headroom, unwinding, early-hit disambiguation, and signal behavior are documented; signal-delivery stops are forwarded, event/group stops abort, and a pending signal is delivered on detach. |
| 14 handle rights | **Corrected.** `CreateRemoteThread` requires five of the six rights; only `PROCESS_SYNCHRONIZE` on the process handle is unused. The mask was left unchanged. |
| 15 CFG/IBT | **Fixed for the stub entry.** Both stubs start with `ENDBR64`/`ENDBR32`; the indirect callee requirement is documented. Native CFG/CET remains unverified locally as stated. |
| 15b variadic AL | **Fixed.** `xor eax, eax` precedes the call and the indirect target uses `R11`; byte tests updated. |
| 16 ABI enums | **Fixed.** One `memdiver_call_sys::Abi` and one `From<Abi> for X86Abi`; `windows::Abi` and `wine32::WineAbi` are gone. |
| 17 validation duplication | **Partially fixed.** Shared region snapshot, `MAX_ARGUMENTS`, and error mapping removed most of the cost and drift; the independent sys-side validation is retained as defense in depth and the layering docs now say so. |
| 18 helpers | **Fixed.** Shared frame validator, `From<X86Error>`, `inspect`, attach handshake, `Detachable`, `MAX_ARGUMENTS`, and `STACK_HEADROOM`. |
| 19 caller orchestration | **Deferred.** The platform-specific constructors remain; a `Backend` enum is a larger refactor and not risk-free. |
| 20 `wine32::run` | **Improved.** `fail_detached` removed 14 repeated blocks; the function is still long but its happy path is now linear. |
| 21 dead frame checks | **Fixed.** Replaced with debug assertions. |
| 22 error chain | **Partly addressed.** `Cleanup` semantics are fixed; the `map_*` functions remain and are documented as context-based. |
| 23 casts/nits | **Accepted.** The remaining `unwrap_or` sentinels are provably unreachable on the supported hosts; no behavior change. |
| 24 nits | **Mostly fixed.** `must_use`, `direct_call`, SAFETY text, call doc, ENDBR, zeroing AL; the remaining allocation/`GetSystemInfo`/poll micro-nits are left as low-priority. |
| 25 tests | **Mostly fixed.** Added: NoCompletion (`ExitThread`), already-traced `Error::Open`, narrow return, Wine module base, early-return 1000-call test. Still open: PE-parser unit test, signal-forwarding test, indirect-call E2E, `Poisoned`/`Leaked` integration. |
| 26 CI | **Fixed.** `--locked` on every command, release tests, Wine cache. |
| 27 harness | **Partly fixed.** `/proc/<pid>/stat` parsing and the unused `data` field; `fixture_path` duplication and the blocking reap remain. |
| 28 API/packaging | **Mostly fixed.** `Address`/`Process` re-export, `wine_module_base`, `is_supported` removed, `repository`, docs moved, `.gitignore` fixed. `windows-sys` remains 0.59 and the 0.1.1/0.1.0 version skew is unchanged (both are release decisions). |
| 29 docs | **Fixed** across the crate docs, README, sys README, and changelog. |

### Final verification

The following were run on the final tree (Linux 7.3.3, stable Rust 1.99.1):

* `cargo fmt --all -- --check`
* `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
* `cargo clippy --workspace --all-targets --locked -- -D warnings`
* `cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu --locked -- -D warnings`
* `cargo clippy --workspace --all-targets --target i686-pc-windows-gnu --locked -- -D warnings`
* `cargo test --workspace --locked` (16 + 43 unit, 22 integration, 2 doc)
* `cargo test --workspace --release --locked`
* `cargo test --workspace --target x86_64-pc-windows-gnu --locked` under Wine (20 integration)
* `cargo test --workspace --target i686-pc-windows-gnu --locked` under Wine (21 integration)
* `cargo test -p memdiver-call-tests --features wine32-tests --test wine32 --locked -- --test-threads=1` under Wine (13 integration)
* `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked`
* `cargo package --list --locked` for both published crates

MSRV 1.85 was not re-run offline (the toolchain cannot be installed in this sandbox); CI
runs it. Nothing was published to crates.io.
