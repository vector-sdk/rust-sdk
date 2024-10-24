//! Utility functions and helpers for the enclave runtime (crate).
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

extern crate core;

use core::arch::asm;

/// A wrapper for the RISC-V RDTIME pseudoinstruction.
///
/// # Returns
///
/// The value returned by the 'rdtime' assembly instructions.
///

#[allow(dead_code)]
pub(crate) fn rdtime() -> u32
{
    let mut x: u32;
    unsafe { asm!("rdtime {x}", x = out(reg) x); }
    return x;
}
