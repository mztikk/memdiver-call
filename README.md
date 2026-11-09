# memdiver-call workspace

An independent implementation of remote function calls on top of
[`memdiver`](https://crates.io/crates/memdiver): call a function inside another
local process on Linux `x86_64` and Windows `x86_64`/`x86`.

This repository is **not** a member of the `memdiver` workspace. It depends on
the published `memdiver = "0.2"` facade only and does not modify, fork, vendor,
or patch `memdiver`.

## Layout

```text
memdiver-call/          Safe API crate (#![forbid(unsafe_code)])
    src/lib.rs          crate docs, feature matrix, example
    src/error.rs        public Error, CallStatus, PlatformError
    src/options.rs      CallAbi, CallOptions
    src/caller.rs       RemoteCaller, pinning protocol, per-call orchestration
    README.md           full feature matrix, requirements, limitations
    CHANGELOG.md
memdiver-call-sys/      Unsafe platform mechanism (all FFI lives here)
    src/linux.rs        ptrace, hardware breakpoint, save/restore/detach
    src/wine32.rs       native Linux -> 32-bit Windows PE under Wine
    src/windows.rs      CreateRemoteThread stub mechanism
    src/stub.rs         generated x64/x86 stub bytes (unit-tested on every host)
    src/frame.rs        SysV AMD64 call-frame layout (unit-tested on every host)
    src/debug.rs        DR7 slot selection and encoding
memdiver-call-tests/    Fixture binary and end-to-end tests (publish = false)
    src/bin/memdiver-call-fixture.rs
    examples/call_fixture.rs
    tests/remote_call.rs
    tests/wine32.rs     opt-in native Linux -> Wine 32-bit suite
    tests/common/mod.rs
docs/                   Design notes, implementation brief, and code review
```

## Quick start

```sh
cargo test --workspace
cargo run -p memdiver-call-tests --example call_fixture
```

Linux tests need permission to `ptrace` the fixture child. With Yama
`ptrace_scope = 1`, tracing a descendant is allowed for a normal user.

## Windows tests

Windows `x86_64` and `x86` tests run under Wine with a **workspace-local** Wine
prefix (ignored by Git):

```sh
WINEPREFIX="$PWD/.wine-x64" WINEDEBUG=-all \
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine \
    cargo test --workspace --target x86_64-pc-windows-gnu

WINEPREFIX="$PWD/.wine-wow64" WINEDEBUG=-all \
    CARGO_TARGET_I686_PC_WINDOWS_GNU_RUNNER=wine \
    cargo test --workspace --target i686-pc-windows-gnu
```

The native-Linux-to-Wine-`x86` tests are opt-in because they need Wine,
MinGW, and a prebuilt i686 fixture:

```sh
cargo build -p memdiver-call-tests --target i686-pc-windows-gnu \
    --bin memdiver-call-fixture
WINEPREFIX="$PWD/target/wine32-test-prefix" WINEDEBUG=-all \
    cargo test -p memdiver-call-tests --features wine32-tests --test wine32
```

Native Windows CI runs the same Windows tests on `x86_64-pc-windows-msvc` and
`i686-pc-windows-msvc`. Wine proves the mechanism; it does not enforce Control
Flow Guard or CET, so native CI is authoritative for those mitigations.

## Quality gate

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps
cargo check --workspace --all-targets --target x86_64-pc-windows-gnu
cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu -- -D warnings
cargo check --workspace --all-targets --target i686-pc-windows-gnu
cargo clippy --workspace --all-targets --target i686-pc-windows-gnu -- -D warnings
cargo package --list -p memdiver-call
cargo package --list -p memdiver-call-sys

# Optional, after building the i686 fixture (see above):
WINEPREFIX="$PWD/target/wine32-test-prefix" WINEDEBUG=-all \
    cargo test -p memdiver-call-tests --features wine32-tests --test wine32
```

## Documentation

* [`memdiver-call/README.md`](memdiver-call/README.md) — feature matrix,
  platform permissions, safety, limitations, observability, and testing.
* Rustdoc: `cargo doc --workspace --no-deps --open`.

## Design notes

* [`docs/investigation.md`](docs/investigation.md) — mechanism options,
  prototypes, and design decisions.
* [`docs/task-brief.md`](docs/task-brief.md) — the implementation brief and
  acceptance checklist.
* [`docs/code-review.md`](docs/code-review.md) — review findings, verification,
  and remediation.

## License

MIT OR Apache-2.0. See [`memdiver-call/LICENSE-MIT`](memdiver-call/LICENSE-MIT)
and [`memdiver-call/LICENSE-APACHE`](memdiver-call/LICENSE-APACHE).
