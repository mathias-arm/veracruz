#[cfg(not(feature = "mesalock_sgx"))]
extern crate autocfg;

#[cfg(not(feature = "mesalock_sgx"))]
use std::env;

#[cfg(not(feature = "mesalock_sgx"))]
fn main() {
    let ac = autocfg::new();
    if ac.probe_type("i128") {
    println!("cargo:rustc-cfg=has_i128");
    } else if env::var_os("CARGO_FEATURE_I128").is_some() {
        panic!("i128 support was not detected!");
    }

    autocfg::rerun_path(file!());
}

#[cfg(feature = "mesalock_sgx")]
fn main() {
    println!("cargo:rustc-cfg=has_i128");
}
