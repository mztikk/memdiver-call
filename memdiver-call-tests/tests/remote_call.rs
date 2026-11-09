//! End-to-end tests through the public API.

mod common;

use std::sync::Arc;
use std::thread;
#[cfg(target_os = "linux")]
use std::time::Duration;

use common::Fixture;
use memdiver::{Address, Process};
use memdiver_call::{CallAbi, CallOptions, Error, RemoteCaller};

/// Value returned by the fixture's `fixture_ping`.
const PING_VALUE: u64 = 0x5049_4E47;

/// Value written by the pointer-argument test.
const STORED_VALUE: u64 = 0xCAFE_BABE;

fn open(fixture: &Fixture) -> RemoteCaller {
    RemoteCaller::open(fixture.pid()).expect("RemoteCaller::open")
}

#[test]
fn open_calls_two_arguments() {
    let mut fixture = Fixture::spawn();
    let caller = open(&fixture);
    // The fixture is blocked in `read(2)` when the call starts.
    let result = caller
        .call(Address::new(fixture.add), &[2, 3], &CallOptions::new())
        .expect("call");
    assert_eq!(result, 5);
    fixture.ping();
}

#[test]
fn new_adopts_a_writable_handle_and_calls_six_arguments() {
    let mut fixture = Fixture::spawn();
    let process = Process::open(fixture.pid()).expect("Process::open");
    let caller = RemoteCaller::new(process).expect("RemoteCaller::new");
    let result = caller
        .call(
            Address::new(fixture.mix),
            &[1, 2, 3, 4, 5, 6],
            &CallOptions::new(),
        )
        .expect("call");
    assert_eq!(result, 91);
    fixture.ping();
}

#[test]
fn zero_argument_call_returns_the_integer_result() {
    let mut fixture = Fixture::spawn();
    let caller = open(&fixture);
    let result = caller
        .call(Address::new(fixture.ping), &[], &CallOptions::new())
        .expect("call");
    assert_eq!(result, PING_VALUE);
    fixture.ping();
}

#[test]
fn narrow_return_value_is_read_from_the_low_bits() {
    let mut fixture = Fixture::spawn();
    let caller = open(&fixture);
    let raw = caller
        .call(Address::new(fixture.flag), &[], &CallOptions::new())
        .expect("flag");
    // The ABI does not define the upper half for a 32-bit return (EDX on x86,
    // the upper RAX bits on x86_64), so the documented contract is a cast.
    assert_eq!(raw as u32, 1);
    fixture.ping();
}

#[test]
fn pointer_argument_writes_target_memory() {
    let mut fixture = Fixture::spawn();
    let caller = open(&fixture);
    caller
        .call(
            Address::new(fixture.store),
            &[fixture.buffer, STORED_VALUE],
            &CallOptions::new(),
        )
        .expect("store");
    let value: u64 = caller
        .process()
        .read_value(Address::new(fixture.buffer))
        .expect("read back");
    assert_eq!(value, STORED_VALUE);
    fixture.ping();
}

#[test]
fn read_only_handle_is_rejected() {
    let fixture = Fixture::spawn();
    let process = Process::open_readonly(fixture.pid()).expect("Process::open_readonly");
    let error = RemoteCaller::new(process).expect_err("read-only handle");
    assert!(
        matches!(error, Error::ReadOnly),
        "unexpected error: {error:?}"
    );
}

#[test]
fn unsupported_abi_is_rejected_before_the_call() {
    let mut fixture = Fixture::spawn();
    let caller = open(&fixture);
    #[cfg(target_arch = "x86_64")]
    {
        let error = caller
            .call(
                Address::new(fixture.add),
                &[2, 3],
                &CallOptions::new().with_abi(CallAbi::Cdecl),
            )
            .expect_err("non-Auto ABI");
        assert!(
            matches!(error, Error::Unsupported { .. }),
            "unexpected error: {error:?}"
        );
    }
    #[cfg(target_arch = "x86")]
    {
        // On 32-bit Windows the non-default conventions are supported and
        // tested separately; `Cdecl` is equivalent to `Auto` here.
        assert_eq!(
            caller
                .call(
                    Address::new(fixture.add),
                    &[2, 3],
                    &CallOptions::new().with_abi(CallAbi::Cdecl)
                )
                .expect("cdecl"),
            5
        );
    }
    fixture.ping();
}

#[test]
fn too_many_arguments_are_rejected() {
    let fixture = Fixture::spawn();
    let caller = open(&fixture);
    let error = caller
        .call(Address::new(fixture.add), &[0; 7], &CallOptions::new())
        .expect_err("seven arguments");
    match error {
        Error::InvalidArgument { index, .. } => assert_eq!(index, 6),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn null_address_is_rejected() {
    let fixture = Fixture::spawn();
    let caller = open(&fixture);
    let error = caller
        .call(Address::NULL, &[], &CallOptions::new())
        .expect_err("null address");
    assert!(
        matches!(error, Error::InvalidAddress { address, .. } if address.is_null()),
        "unexpected error: {error:?}"
    );
}

#[test]
fn non_executable_address_is_rejected() {
    let mut fixture = Fixture::spawn();
    let caller = open(&fixture);
    let error = caller
        .call(Address::new(fixture.buffer), &[], &CallOptions::new())
        .expect_err("data address");
    match error {
        Error::InvalidAddress { address, .. } => assert_eq!(address.get(), fixture.buffer),
        other => panic!("unexpected error: {other:?}"),
    }
    // Nothing was called, so the fixture is still responsive.
    fixture.ping();
}

#[test]
fn target_exit_during_call_is_an_error_not_a_hang() {
    let fixture = Fixture::spawn();
    let caller = open(&fixture);
    let error = caller
        .call(Address::new(fixture.exit), &[], &CallOptions::new())
        .expect_err("target exit");
    let failure = match &error {
        Error::Cleanup {
            call: Some(inner), ..
        } => inner.as_ref(),
        other => other,
    };
    assert!(
        matches!(
            failure,
            Error::CallFailed { .. } | Error::TargetExited { .. } | Error::Memory { .. }
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn consecutive_calls_keep_the_target_running() {
    let mut fixture = Fixture::spawn();
    let caller = open(&fixture);
    for _ in 0..3 {
        let result = caller
            .call(Address::new(fixture.add), &[20, 22], &CallOptions::new())
            .expect("call");
        assert_eq!(result, 42);
        fixture.ping();
    }
}

#[test]
fn concurrent_calls_are_serialized() {
    let mut fixture = Fixture::spawn();
    let caller = Arc::new(open(&fixture));
    let function = fixture.add;
    let mut threads = Vec::new();
    for _ in 0..4 {
        let caller = Arc::clone(&caller);
        threads.push(thread::spawn(move || {
            caller.call(Address::new(function), &[2, 3], &CallOptions::new())
        }));
    }
    for thread in threads {
        let result = thread.join().expect("thread").expect("call");
        assert_eq!(result, 5);
    }
    fixture.ping();
}

#[test]
fn call_export_resolves_executable_exports() {
    let mut fixture = Fixture::spawn();
    let caller = open(&fixture);
    let result = caller
        .call_export(&fixture.module, "fixture_add", &[2, 3], &CallOptions::new())
        .expect("call_export");
    assert_eq!(result, 5);
    fixture.ping();
}

#[test]
fn call_export_keeps_resolution_errors_structured() {
    let fixture = Fixture::spawn();
    let caller = open(&fixture);
    let error = caller
        .call_export(&fixture.module, "not_an_export", &[], &CallOptions::new())
        .expect_err("missing export");
    assert!(
        matches!(error, Error::ExportNotFound { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn call_export_rejects_a_data_export() {
    let mut fixture = Fixture::spawn();
    let caller = open(&fixture);
    let error = caller
        .call_export(&fixture.module, "FIXTURE_DATA", &[], &CallOptions::new())
        .expect_err("data export");
    assert!(
        matches!(error, Error::InvalidAddress { .. }),
        "unexpected error: {error:?}"
    );
    fixture.ping();
}

#[cfg(target_os = "linux")]
#[test]
fn thread_option_accepts_only_the_main_thread() {
    let mut fixture = Fixture::spawn();
    let caller = open(&fixture);
    let pid = fixture.pid();
    let result = caller
        .call(
            Address::new(fixture.ping),
            &[],
            &CallOptions::new().with_thread(pid),
        )
        .expect("main thread");
    assert_eq!(result, PING_VALUE);
    let error = caller
        .call(
            Address::new(fixture.ping),
            &[],
            &CallOptions::new().with_thread(pid.wrapping_add(1)),
        )
        .expect_err("non-main thread");
    assert!(
        matches!(error, Error::Unsupported { .. }),
        "unexpected error: {error:?}"
    );
    fixture.ping();
}

#[cfg(target_os = "linux")]
#[test]
fn calling_the_running_function_returns_its_result() {
    // The fixture spins on `fixture_add(2, 3)`. Calling the same address with
    // (40, 2) must return 42 even when the interrupted RIP is inside the
    // function: the return breakpoint then fires early while the callee
    // executes that instruction, and the resume-flag path must step over it.
    let fixture = Fixture::spawn_spinning_add();
    let caller = open(&fixture);
    for _ in 0..1000 {
        match caller.call(Address::new(fixture.add), &[40, 2], &CallOptions::new()) {
            Ok(42) => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn call_after_target_exit_reports_target_exited() {
    let fixture = Fixture::spawn();
    let caller = open(&fixture);
    let function = fixture.add;
    let pid = fixture.pid();
    drop(fixture);
    // Give the kernel a moment to reap the child and drop `/proc/<pid>`.
    std::thread::sleep(Duration::from_millis(50));
    let error = caller
        .call(Address::new(function), &[2, 3], &CallOptions::new())
        .expect_err("dead target");
    assert!(
        matches!(error, Error::TargetExited { pid: reported } if reported == pid),
        "unexpected error: {error:?}"
    );
}

#[cfg(windows)]
#[test]
fn exit_thread_reports_no_completion() {
    let mut fixture = Fixture::spawn();
    let caller = open(&fixture);
    let error = caller
        .call(Address::new(fixture.exit_thread), &[], &CallOptions::new())
        .expect_err("thread exit");
    assert!(
        matches!(
            error,
            Error::CallFailed {
                status: memdiver_call::CallStatus::NoCompletion,
                ..
            }
        ),
        "unexpected error: {error:?}"
    );
    fixture.ping();
}

#[cfg(target_os = "linux")]
#[test]
fn open_on_an_already_traced_target_is_reported() {
    let mut fixture = Fixture::spawn();
    let pid = fixture.pid() as libc::pid_t;
    // SAFETY: the fixture is our child; these are documented ptrace requests
    // with null address/data arguments.
    unsafe {
        assert_eq!(
            libc::ptrace(
                libc::PTRACE_SEIZE,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            ),
            0
        );
        assert_eq!(
            libc::ptrace(
                libc::PTRACE_INTERRUPT,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            ),
            0
        );
        let mut status = 0;
        assert_eq!(libc::waitpid(pid, &mut status, libc::__WALL), pid);
    }
    let error = RemoteCaller::open(fixture.pid()).expect_err("already traced");
    assert!(
        matches!(error, Error::Open { .. }),
        "unexpected error: {error:?}"
    );
    // SAFETY: we are the tracer and the tracee is stopped.
    unsafe {
        assert_eq!(
            libc::ptrace(
                libc::PTRACE_DETACH,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            ),
            0
        );
    }
    fixture.ping();
}

#[cfg(windows)]
#[test]
fn thread_option_is_unsupported_on_windows() {
    let mut fixture = Fixture::spawn();
    let caller = open(&fixture);
    let error = caller
        .call(
            Address::new(fixture.ping),
            &[],
            &CallOptions::new().with_thread(fixture.pid()),
        )
        .expect_err("thread option");
    assert!(
        matches!(error, Error::Unsupported { .. }),
        "unexpected error: {error:?}"
    );
    fixture.ping();
}

#[cfg(all(windows, target_arch = "x86"))]
#[test]
fn x86_calling_conventions_dispatch_correctly() {
    let mut fixture = Fixture::spawn();
    let caller = open(&fixture);
    let stdcall = caller
        .call(
            Address::new(fixture.stdcall),
            &[2, 3],
            &CallOptions::new().with_abi(CallAbi::Stdcall),
        )
        .expect("stdcall");
    assert_eq!(stdcall, 5);
    let fastcall = caller
        .call(
            Address::new(fixture.fastcall),
            &[2, 3],
            &CallOptions::new().with_abi(CallAbi::Fastcall),
        )
        .expect("fastcall");
    assert_eq!(fastcall, 5);
    let thiscall = caller
        .call(
            Address::new(fixture.thiscall),
            &[100, 2, 3],
            &CallOptions::new().with_abi(CallAbi::Thiscall),
        )
        .expect("thiscall");
    assert_eq!(thiscall, 105);
    fixture.ping();
}

#[cfg(all(windows, target_arch = "x86"))]
#[test]
fn x86_wide_arguments_use_two_stack_slots() {
    let mut fixture = Fixture::spawn();
    let caller = open(&fixture);

    let a = 0x1_0000_0003u64;
    let b = 0x2_0000_0005u64;
    let options = CallOptions::new().with_wide_arguments(&[0, 1]);
    assert_eq!(
        caller
            .call(Address::new(fixture.add64), &[a, b], &options)
            .expect("add64"),
        a.wrapping_add(b)
    );

    let a32 = 7u32;
    let b64 = 0x1_0000_0009u64;
    let c32 = 0xAAAAu32;
    let d64 = 0x2_0000_000Bu64;
    let expected =
        u64::from(a32) ^ b64.wrapping_mul(3) ^ (u64::from(c32) << 32) ^ d64.wrapping_mul(5);
    let options = CallOptions::new().with_wide_arguments(&[1, 3]);
    assert_eq!(
        caller
            .call(
                Address::new(fixture.mix64),
                &[u64::from(a32), b64, u64::from(c32), d64],
                &options,
            )
            .expect("mix64"),
        expected
    );

    let options = CallOptions::new()
        .with_wide_arguments(&[0, 1])
        .with_abi(CallAbi::Stdcall);
    assert_eq!(
        caller
            .call(Address::new(fixture.stdcall64), &[10, 20], &options)
            .expect("stdcall64"),
        30
    );

    let transport = 0x1122_3344_5566_7788u64;
    let seat = 7u32;
    let expected = u64::from(100u32) ^ transport ^ (u64::from(seat) << 32);
    let options = CallOptions::new()
        .with_wide_arguments(&[1])
        .with_abi(CallAbi::Thiscall);
    assert_eq!(
        caller
            .call(
                Address::new(fixture.thiscall64),
                &[100, transport, u64::from(seat)],
                &options,
            )
            .expect("thiscall64"),
        expected
    );
    fixture.ping();
}

#[cfg(target_pointer_width = "64")]
#[test]
fn wide_arguments_are_unsupported_on_64_bit_targets() {
    let fixture = Fixture::spawn();
    let caller = open(&fixture);
    let error = caller
        .call(
            Address::new(fixture.add),
            &[2, 3],
            &CallOptions::new().with_wide_arguments(&[0]),
        )
        .expect_err("wide arguments on 64-bit");
    assert!(
        matches!(error, Error::Unsupported { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn remote_caller_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RemoteCaller>();
}
