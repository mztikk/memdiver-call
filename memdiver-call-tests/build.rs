//! Exports fixture symbols so `call_export` can be tested.
//!
//! On Linux the binary is linked with `--export-dynamic`, which puts the
//! symbols in `.dynsym`. On Windows a `.def` file creates a PE export table.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    match std::env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("linux") => {
            println!("cargo:rustc-link-arg-bin=memdiver-call-fixture=-Wl,--export-dynamic");
        }
        Ok("windows") => {
            let out = std::env::var("OUT_DIR").expect("OUT_DIR");
            let definition = std::path::Path::new(&out).join("memdiver-call-fixture.def");
            std::fs::write(&definition, "EXPORTS\n  fixture_add\n  FIXTURE_DATA\n")
                .expect("write fixture .def");
            if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
                println!(
                    "cargo:rustc-link-arg-bin=memdiver-call-fixture=/DEF:{}",
                    definition.display()
                );
            } else {
                // GNU ld for PE reads `.def` files passed as input files.
                println!(
                    "cargo:rustc-link-arg-bin=memdiver-call-fixture={}",
                    definition.display()
                );
            }
        }
        _ => {}
    }
}
