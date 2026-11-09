//! Native Linux caller into a 32-bit Windows PE under Wine.
//!
//! This suite is opt-in because it needs Wine, MinGW, and a prebuilt i686
//! fixture:
//!
//! ```sh
//! cargo build -p memdiver-call-tests --target i686-pc-windows-gnu \
//!     --bin memdiver-call-fixture
//! WINEPREFIX="$PWD/target/wine32-test-prefix" WINEDEBUG=-all \
//!     cargo test -p memdiver-call-tests --features wine32-tests --test wine32
//! ```
//!
//! The test process becomes a child subreaper so the PE-hosting process stays
//! traceable after the `wine` launcher exits.

#![cfg(all(target_os = "linux", feature = "wine32-tests"))]

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use memdiver::Address;
use memdiver_call::{CallAbi, CallOptions, Error, RemoteCaller};

/// Value returned by the fixture's `fixture_ping`.
const PING_VALUE: u64 = 0x5049_4E47;

/// Value written by the pointer-argument test.
const STORED_VALUE: u64 = 0xCAFE_BABE;

/// Serializes Wine fixtures: one prefix, one spinning 32-bit process at a time.
static SERIAL: Mutex<()> = Mutex::new(());

/// Set once per test process.
static SUBREAPER: Once = Once::new();

/// Makes each fixture's tag unique.
static NEXT_TAG: AtomicU64 = AtomicU64::new(0);

fn init() {
    SUBREAPER.call_once(|| {
        // SAFETY: `PR_SET_CHILD_SUBREAPER` takes scalar arguments.
        let _ = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    });
}

/// Returns the workspace target directory (`<target>/<profile>/deps/...`).
fn target_directory() -> PathBuf {
    let executable = std::env::current_exe().expect("current executable");
    let deps = executable.parent().expect("deps directory");
    let profile = deps.parent().expect("profile directory");
    profile.parent().expect("target directory").to_path_buf()
}

/// Locates the i686 fixture binary.
fn fixture_path() -> PathBuf {
    if let Some(path) = std::env::var_os("MEMDIVER_CALL_WINE32_FIXTURE") {
        return PathBuf::from(path);
    }
    let path = target_directory()
        .join("i686-pc-windows-gnu")
        .join("debug")
        .join("memdiver-call-fixture.exe");
    assert!(
        path.exists(),
        "missing 32-bit fixture at {}; run `cargo build -p memdiver-call-tests \
         --target i686-pc-windows-gnu --bin memdiver-call-fixture`",
        path.display()
    );
    path
}

/// Returns a writable Wine prefix.
fn wine_prefix() -> PathBuf {
    let prefix = std::env::var_os("MEMDIVER_CALL_WINEPREFIX")
        .map(PathBuf::from)
        .unwrap_or_else(|| target_directory().join("wine32-test-prefix"));
    fs::create_dir_all(&prefix).expect("create Wine prefix");
    prefix
}

/// A spinning 32-bit Windows fixture hosted by Wine.
struct WineFixture {
    launcher: Child,
    pid: i32,
    _serial: std::sync::MutexGuard<'static, ()>,
    add: u64,
    mix: u64,
    store: u64,
    ping: u64,
    exit: u64,
    buffer: u64,
    tick: u64,
    stdcall: u64,
    thiscall: u64,
    fastcall: u64,
    add64: u64,
    mix64: u64,
    stdcall64: u64,
    thiscall64: u64,
}

impl WineFixture {
    fn spawn() -> Self {
        let serial = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        init();
        let tag = format!(
            "memdiver-call-{}-{}",
            std::process::id(),
            NEXT_TAG.fetch_add(1, Ordering::Relaxed)
        );
        let mut launcher = Command::new("wine")
            .arg(fixture_path())
            .arg(format!("--tag={tag}"))
            .env("WINEPREFIX", wine_prefix())
            .env("WINEDEBUG", "-all")
            .env("MEMDIVER_CALL_FIXTURE_SPIN", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn wine; is Wine installed?");

        let stdout = launcher.stdout.take().expect("fixture stdout");
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) if line.starts_with("READY ") => {
                        let _ = sender.send(line.trim().to_owned());
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
        let ready = match receiver.recv_timeout(Duration::from_secs(30)) {
            Ok(line) => line,
            Err(_) => {
                let _ = launcher.kill();
                let _ = launcher.wait();
                panic!("Wine fixture did not print READY within 30s");
            }
        };
        let fields = parse_ready(&ready);
        let pid = find_pe_process(
            &tag,
            std::process::id(),
            launcher.id(),
            Duration::from_secs(30),
        )
        .unwrap_or_else(|| {
            let _ = launcher.kill();
            let _ = launcher.wait();
            panic!("could not find the PE-hosting process with tag {tag}");
        });

        Self {
            launcher,
            pid: pid as i32,
            _serial: serial,
            add: number(&fields, "add"),
            mix: number(&fields, "mix"),
            store: number(&fields, "store"),
            ping: number(&fields, "ping"),
            exit: number(&fields, "exit"),
            buffer: number(&fields, "buffer"),
            tick: number(&fields, "tick"),
            stdcall: number(&fields, "stdcall"),
            thiscall: number(&fields, "thiscall"),
            fastcall: number(&fields, "fastcall"),
            add64: number(&fields, "add64"),
            mix64: number(&fields, "mix64"),
            stdcall64: number(&fields, "stdcall64"),
            thiscall64: number(&fields, "thiscall64"),
        }
    }

    fn open(&self) -> RemoteCaller {
        RemoteCaller::open_wine(self.pid as u32)
            .unwrap_or_else(|error| panic!("open_wine: {error:?}"))
    }

    fn options(&self) -> CallOptions {
        CallOptions::new().with_safe_point(Address::new(self.tick))
    }
}

impl Drop for WineFixture {
    fn drop(&mut self) {
        // SAFETY: the PID is our descendant (subreaper) or the launcher's
        // child; killing it is the test cleanup.
        unsafe {
            libc::kill(self.pid, libc::SIGKILL);
            let mut status = 0;
            libc::waitpid(self.pid, &mut status, 0);
        }
        let _ = self.launcher.kill();
        let _ = self.launcher.wait();
    }
}

/// Parses `key=value` fields after the `READY` marker.
fn parse_ready(line: &str) -> HashMap<String, String> {
    line.split_whitespace()
        .skip(1)
        .filter_map(|field| field.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

/// Parses a hexadecimal field.
fn number(fields: &HashMap<String, String>, key: &str) -> u64 {
    let raw = fields
        .get(key)
        .unwrap_or_else(|| panic!("READY line has no {key}: {fields:?}"));
    u64::from_str_radix(raw.trim_start_matches("0x"), 16)
        .unwrap_or_else(|_| panic!("bad {key}={raw}"))
}

/// Finds the Linux process that hosts the PE, matching the unique tag.
fn find_pe_process(tag: &str, parent: u32, launcher: u32, timeout: Duration) -> Option<u32> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        for entry in fs::read_dir("/proc").ok()? {
            let Ok(entry) = entry else {
                continue;
            };
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let Ok(cmdline) = fs::read(format!("/proc/{pid}/cmdline")) else {
                continue;
            };
            let cmdline = String::from_utf8_lossy(&cmdline).replace('\0', " ");
            if !cmdline.contains(tag) || !cmdline.contains("Z:\\") {
                continue;
            }
            let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
                continue;
            };
            let ppid = stat
                .split_whitespace()
                .nth(3)
                .and_then(|value| value.parse::<u32>().ok());
            if ppid == Some(parent) || ppid == Some(launcher) {
                return Some(pid);
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
    None
}

#[test]
fn wine_module_base_is_reported() {
    let fixture = WineFixture::spawn();
    let caller = fixture.open();
    assert!(
        caller.wine_module_base().is_some(),
        "open_wine must report the PE main-module base"
    );
}

#[test]
fn calls_with_a_safe_point() {
    let fixture = WineFixture::spawn();
    let caller = fixture.open();
    let options = fixture.options();
    assert_eq!(
        caller
            .call(Address::new(fixture.ping), &[], &options)
            .expect("ping"),
        PING_VALUE
    );
    assert_eq!(
        caller
            .call(Address::new(fixture.add), &[2, 3], &options)
            .expect("add"),
        5
    );
    assert_eq!(
        caller
            .call(Address::new(fixture.mix), &[1, 2, 3, 4, 5, 6], &options)
            .expect("mix"),
        91
    );
}

#[test]
fn pointer_arguments_and_x86_conventions() {
    let fixture = WineFixture::spawn();
    let caller = fixture.open();
    let options = fixture.options();
    caller
        .call(
            Address::new(fixture.store),
            &[fixture.buffer, STORED_VALUE],
            &options,
        )
        .expect("store");
    let value: u64 = caller
        .process()
        .read_value(Address::new(fixture.buffer))
        .expect("read back");
    assert_eq!(value, STORED_VALUE);

    assert_eq!(
        caller
            .call(
                Address::new(fixture.stdcall),
                &[4, 5],
                &options.clone().with_abi(CallAbi::Stdcall),
            )
            .expect("stdcall"),
        9
    );
    assert_eq!(
        caller
            .call(
                Address::new(fixture.fastcall),
                &[6, 7],
                &options.clone().with_abi(CallAbi::Fastcall),
            )
            .expect("fastcall"),
        13
    );
    assert_eq!(
        caller
            .call(
                Address::new(fixture.thiscall),
                &[100, 2, 3],
                &options.with_abi(CallAbi::Thiscall),
            )
            .expect("thiscall"),
        105
    );
}

#[test]
fn wide_arguments_use_two_stack_slots() {
    let fixture = WineFixture::spawn();
    let caller = fixture.open();

    // cdecl: fixture_add64(a: u64, b: u64).
    let a = 0x1_0000_0003u64;
    let b = 0x2_0000_0005u64;
    let options = fixture.options().with_wide_arguments(&[0, 1]);
    assert_eq!(
        caller
            .call(Address::new(fixture.add64), &[a, b], &options)
            .expect("add64"),
        a.wrapping_add(b)
    );

    // cdecl mixed widths: fixture_mix64(a: u32, b: u64, c: u32, d: u64).
    let a32 = 7u32;
    let b64 = 0x1_0000_0009u64;
    let c32 = 0xAAAAu32;
    let d64 = 0x2_0000_000Bu64;
    let expected =
        u64::from(a32) ^ b64.wrapping_mul(3) ^ (u64::from(c32) << 32) ^ d64.wrapping_mul(5);
    let options = fixture.options().with_wide_arguments(&[1, 3]);
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

    // stdcall with two wide arguments.
    let options = fixture
        .options()
        .with_wide_arguments(&[0, 1])
        .with_abi(CallAbi::Stdcall);
    assert_eq!(
        caller
            .call(Address::new(fixture.stdcall64), &[10, 20], &options)
            .expect("stdcall64"),
        30
    );

    // thiscall with a wide transport and a narrow seat.
    let transport = 0x1122_3344_5566_7788u64;
    let seat = 7u32;
    let expected = u64::from(100u32) ^ transport ^ (u64::from(seat) << 32);
    let options = fixture
        .options()
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
}

#[test]
fn wide_argument_validation() {
    let fixture = WineFixture::spawn();
    let caller = fixture.open();

    let options = fixture.options().with_wide_arguments(&[2]);
    let error = caller
        .call(Address::new(fixture.add), &[1, 2], &options)
        .expect_err("out of range");
    assert!(
        matches!(error, Error::InvalidArgument { index: 2, .. }),
        "unexpected error: {error:?}"
    );

    let options = fixture.options().with_wide_arguments(&[0, 0]);
    let error = caller
        .call(Address::new(fixture.add), &[1, 2], &options)
        .expect_err("duplicate");
    assert!(
        matches!(error, Error::InvalidArgument { index: 0, .. }),
        "unexpected error: {error:?}"
    );

    let options = fixture.options().with_wide_arguments(&[0]);
    let error = caller
        .call(Address::new(fixture.add), &[1, 0x1_0000_0000], &options)
        .expect_err("narrow overflow");
    assert!(
        matches!(error, Error::InvalidArgument { index: 1, .. }),
        "unexpected error: {error:?}"
    );

    // `this` is a register argument and cannot be 64-bit.
    let options = fixture
        .options()
        .with_wide_arguments(&[0])
        .with_abi(CallAbi::Thiscall);
    let error = caller
        .call(Address::new(fixture.thiscall64), &[1, 2, 3], &options)
        .expect_err("wide this");
    assert!(
        matches!(error, Error::Unsupported { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn safe_point_timeout_is_reported() {
    let fixture = WineFixture::spawn();
    let caller = fixture.open();
    // `fixture_exit` is executable but never called by the spin loop.
    let options = CallOptions::new()
        .with_safe_point(Address::new(fixture.exit))
        .with_safe_point_timeout(Duration::from_millis(150));
    let error = caller
        .call(Address::new(fixture.ping), &[], &options)
        .expect_err("safe point timeout");
    assert!(
        matches!(error, Error::SafePointTimeout { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn non_executable_safe_point_is_rejected_before_attaching() {
    let fixture = WineFixture::spawn();
    let caller = fixture.open();
    let options = CallOptions::new().with_safe_point(Address::new(fixture.buffer));
    let error = caller
        .call(Address::new(fixture.ping), &[], &options)
        .expect_err("data safe point");
    assert!(
        matches!(error, Error::InvalidAddress { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn argument_and_address_validation() {
    let fixture = WineFixture::spawn();
    let caller = fixture.open();
    let options = fixture.options();

    let error = caller
        .call(Address::new(fixture.add), &[0; 7], &options)
        .expect_err("seven arguments");
    assert!(
        matches!(error, Error::InvalidArgument { index: 6, .. }),
        "unexpected error: {error:?}"
    );

    let error = caller
        .call(
            Address::new(fixture.add),
            &[u64::from(u32::MAX) + 1, 2],
            &options,
        )
        .expect_err("wide argument");
    assert!(
        matches!(error, Error::InvalidArgument { index: 0, .. }),
        "unexpected error: {error:?}"
    );

    let error = caller
        .call(
            Address::new(fixture.add),
            &[2, 3],
            &CallOptions::new().with_safe_point(Address::new(fixture.add)),
        )
        .expect_err("safe point equals function");
    assert!(
        matches!(error, Error::InvalidArgument { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn call_export_is_unsupported_on_wine() {
    let fixture = WineFixture::spawn();
    let caller = fixture.open();
    let error = caller
        .call_export("anything", "anything", &[], &fixture.options())
        .expect_err("call_export");
    assert!(
        matches!(error, Error::Unsupported { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn non_wine_process_is_rejected() {
    let mut child = Command::new("sleep").arg("5").spawn().expect("spawn sleep");
    let error = RemoteCaller::open_wine(child.id()).expect_err("native child");
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        matches!(error, Error::Unsupported { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn thread_selection_only_allows_the_main_thread() {
    let fixture = WineFixture::spawn();
    let caller = fixture.open();
    let pid = fixture.pid as u32;
    let options = fixture.options();
    assert_eq!(
        caller
            .call(
                Address::new(fixture.ping),
                &[],
                &options.clone().with_thread(pid),
            )
            .expect("main thread"),
        PING_VALUE
    );
    let error = caller
        .call(
            Address::new(fixture.ping),
            &[],
            &options.with_thread(pid.wrapping_add(1)),
        )
        .expect_err("other thread");
    assert!(
        matches!(error, Error::Unsupported { .. }),
        "unexpected error: {error:?}"
    );
}

#[test]
fn concurrent_calls_are_serialized() {
    let fixture = WineFixture::spawn();
    let caller = Arc::new(fixture.open());
    let add = fixture.add;
    let tick = fixture.tick;
    let mut threads = Vec::new();
    for _ in 0..4 {
        let caller = Arc::clone(&caller);
        threads.push(thread::spawn(move || {
            caller.call(
                Address::new(add),
                &[2, 3],
                &CallOptions::new().with_safe_point(Address::new(tick)),
            )
        }));
    }
    for thread in threads {
        assert_eq!(thread.join().expect("thread").expect("call"), 5);
    }
}

#[test]
fn target_exit_during_call_is_an_error() {
    let fixture = WineFixture::spawn();
    let caller = fixture.open();
    let error = caller
        .call(Address::new(fixture.exit), &[], &fixture.options())
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
