//! Build options
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

fn main() {
    // Always link statically as no libraries are available in the enclave
    println!("cargo:rustc-link-arg=-static");
    // No standard libraries available in the enclave
    println!("cargo:rustc-link-arg=-nostdlib");
}
