# memdiver-call-sys

Unsafe platform mechanism behind
[`memdiver-call`](https://crates.io/crates/memdiver-call).

This crate owns every `unsafe` block in the project:

* Linux `x86_64`: `ptrace` attach/interrupt, register and floating-point state,
  hardware execution breakpoints, red-zone-safe call frames, restore, detach.
* Windows `x86_64` and `x86`: `OpenProcess`, remote stub allocation, W^X
  protection changes, `CreateRemoteThread`, wait/exit-code checks, and
  allocation cleanup.

It deliberately contains no policy: the safe crate validates the request and
maps these errors into its public error type. Do not depend on this crate
directly unless you are implementing `memdiver-call` itself.

## Safety

The functions are unsafe platform operations. Invalid addresses, a mismatched
calling convention, or a target that exits at the wrong moment can crash or
corrupt the target. Every `unsafe` block carries a `SAFETY` comment naming the
invariant it relies on.

## Platforms

Linux `x86_64`, Windows `x86_64`, and Windows `x86`. Other hosts fail to
compile with an explicit diagnostic.

## License

MIT OR Apache-2.0.
