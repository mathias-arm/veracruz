#[cfg(not(feature = "mesalock_sgx"))]
extern crate autocfg;

#[cfg(not(feature = "mesalock_sgx"))]
fn main() {
    let ac = autocfg::new();
    ac.emit_sysroot_crate("std");
    autocfg::rerun_path(file!());
    println!("cargo:rustc-cfg=has_std");
}

#[cfg(feature = "mesalock_sgx")]
fn main() {
    println!("cargo:rustc-cfg=has_std");
}
