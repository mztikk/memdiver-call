//! Minimal end-to-end example: spawn the test fixture, call one of its
//! functions, and print the result.
//!
//! Build the fixture first, then run the example:
//!
//! ```sh
//! cargo build --workspace
//! cargo run -p memdiver-call-tests --example call_fixture
//! ```

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use memdiver::Address;
use memdiver_call::{CallOptions, RemoteCaller};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new(fixture_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut stdout = BufReader::new(child.stdout.take().expect("fixture stdout"));
    let mut ready = String::new();
    stdout.read_line(&mut ready)?;

    let address = ready
        .split_whitespace()
        .find_map(|field| field.strip_prefix("add="))
        .expect("READY line contains add=0x...");
    let add = u64::from_str_radix(address.trim_start_matches("0x"), 16)?;

    let caller = RemoteCaller::open(child.id())?;
    let value = caller.call(Address::new(add), &[2, 3], &CallOptions::new())?;
    println!("fixture_add(2, 3) -> {value}");

    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

/// Finds the fixture binary next to this example's executable.
fn fixture_path() -> PathBuf {
    let name = format!("memdiver-call-fixture{}", std::env::consts::EXE_SUFFIX);
    if let Ok(executable) = std::env::current_exe() {
        if let Some(directory) = executable.parent() {
            for candidate in [
                directory.join(&name),
                directory.join("..").join(&name),
                directory.join("..").join("..").join(&name),
            ] {
                if candidate.exists() {
                    return candidate;
                }
            }
        }
    }
    PathBuf::from(name)
}
