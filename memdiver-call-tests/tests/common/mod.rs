//! Shared harness: spawns the fixture and communicates with it.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// A running fixture process.
pub(crate) struct Fixture {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// Address of `fixture_add`.
    pub(crate) add: u64,
    /// Address of `fixture_mix`.
    pub(crate) mix: u64,
    /// Address of `fixture_store`.
    pub(crate) store: u64,
    /// Address of `fixture_ping`.
    pub(crate) ping: u64,
    /// Address of `fixture_flag`, which returns a 32-bit value.
    pub(crate) flag: u64,
    /// Address of `fixture_exit`.
    pub(crate) exit: u64,
    /// Address of `fixture_exit_thread` (Windows only).
    #[cfg(windows)]
    pub(crate) exit_thread: u64,
    /// Address of the fixture's scratch buffer.
    pub(crate) buffer: u64,
    /// Address of the fixture's data export.
    pub(crate) data: u64,
    /// File name of the fixture module, for `call_export`.
    pub(crate) module: String,
    /// Address of `fixture_stdcall_add` (Windows `x86` only).
    #[cfg(all(windows, target_arch = "x86"))]
    pub(crate) stdcall: u64,
    /// Address of `fixture_fastcall_add` (Windows `x86` only).
    #[cfg(all(windows, target_arch = "x86"))]
    pub(crate) fastcall: u64,
    /// Address of `fixture_thiscall_add` (Windows `x86` only).
    #[cfg(all(windows, target_arch = "x86"))]
    pub(crate) thiscall: u64,
    /// Address of `fixture_add64` (Windows `x86` only).
    #[cfg(all(windows, target_arch = "x86"))]
    pub(crate) add64: u64,
    /// Address of `fixture_mix64` (Windows `x86` only).
    #[cfg(all(windows, target_arch = "x86"))]
    pub(crate) mix64: u64,
    /// Address of `fixture_stdcall64` (Windows `x86` only).
    #[cfg(all(windows, target_arch = "x86"))]
    pub(crate) stdcall64: u64,
    /// Address of `fixture_thiscall64` (Windows `x86` only).
    #[cfg(all(windows, target_arch = "x86"))]
    pub(crate) thiscall64: u64,
}

impl Fixture {
    /// Spawns the fixture and waits for its `READY` line.
    pub(crate) fn spawn() -> Self {
        Self::spawn_with_env(&[])
    }

    /// Spawns the fixture spinning on `fixture_add(2, 3)` only.
    pub(crate) fn spawn_spinning_add() -> Self {
        Self::spawn_with_env(&[("MEMDIVER_CALL_FIXTURE_SPIN_ADD", "1")])
    }

    /// Spawns the fixture with additional environment variables.
    fn spawn_with_env(envs: &[(&str, &str)]) -> Self {
        let path = fixture_path();
        let module = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut command = Command::new(&path);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for (key, value) in envs {
            command.env(key, value);
        }
        let mut child = command
            .spawn()
            .unwrap_or_else(|error| panic!("failed to spawn {}: {error}", path.display()));
        let stdin = child.stdin.take().expect("fixture stdin");
        let mut stdout = BufReader::new(child.stdout.take().expect("fixture stdout"));

        let mut line = String::new();
        stdout.read_line(&mut line).expect("read READY");
        let fields = parse_fields(line.trim());
        let number = |key: &str| -> u64 {
            let value = fields
                .get(key)
                .unwrap_or_else(|| panic!("READY line has no {key}: {line:?}"));
            let digits = value.strip_prefix("0x").unwrap_or(value);
            u64::from_str_radix(digits, 16).unwrap_or_else(|_| panic!("bad {key}: {value:?}"))
        };
        let pid: u32 = fields
            .get("pid")
            .expect("pid field")
            .parse()
            .expect("decimal pid");

        let fixture = Self {
            child,
            stdin,
            stdout,
            add: number("add"),
            mix: number("mix"),
            store: number("store"),
            ping: number("ping"),
            flag: number("flag"),
            exit: number("exit"),
            #[cfg(windows)]
            exit_thread: number("exit_thread"),
            buffer: number("buffer"),
            data: number("data"),
            module,
            #[cfg(all(windows, target_arch = "x86"))]
            stdcall: number("stdcall"),
            #[cfg(all(windows, target_arch = "x86"))]
            fastcall: number("fastcall"),
            #[cfg(all(windows, target_arch = "x86"))]
            thiscall: number("thiscall"),
            #[cfg(all(windows, target_arch = "x86"))]
            add64: number("add64"),
            #[cfg(all(windows, target_arch = "x86"))]
            mix64: number("mix64"),
            #[cfg(all(windows, target_arch = "x86"))]
            stdcall64: number("stdcall64"),
            #[cfg(all(windows, target_arch = "x86"))]
            thiscall64: number("thiscall64"),
        };
        assert_eq!(fixture.pid(), pid, "Child::id must match the printed pid");
        fixture
    }

    /// Returns the fixture PID.
    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Sends one line to the fixture.
    pub(crate) fn send(&mut self, line: &str) {
        self.stdin.write_all(line.as_bytes()).expect("write stdin");
        self.stdin.write_all(b"\n").expect("write newline");
        self.stdin.flush().expect("flush stdin");
    }

    /// Sends `PING` and asserts that the fixture answers `PONG`.
    pub(crate) fn ping(&mut self) {
        self.send("PING");
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read PONG");
        assert_eq!(
            line.trim(),
            "PONG",
            "fixture did not answer PING; it may have died or stayed stopped"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.stdin.write_all(b"STOP\n");
        let _ = self.stdin.flush();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Locates the fixture binary next to the running test executable.
///
/// `CARGO_BIN_EXE_*` is a compile-time host path. Under Wine that path is not
/// a Windows path, so the sibling lookup wins there.
fn fixture_path() -> PathBuf {
    let name = format!("memdiver-call-fixture{}", std::env::consts::EXE_SUFFIX);
    if let Ok(executable) = std::env::current_exe() {
        if let Some(directory) = executable.parent() {
            for candidate in [directory.join(&name), directory.join("..").join(&name)] {
                if candidate.exists() {
                    return candidate;
                }
            }
        }
    }
    PathBuf::from(env!("CARGO_BIN_EXE_memdiver-call-fixture"))
}

/// Parses `key=value` fields after the `READY` marker.
fn parse_fields(line: &str) -> HashMap<String, String> {
    assert!(
        line.starts_with("READY "),
        "unexpected fixture output: {line:?}"
    );
    line.split_whitespace()
        .skip(1)
        .filter_map(|field| field.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}
