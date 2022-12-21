//! Utility functions and helpers for the enclave runtime (crate).
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
use core::arch::asm;

/// A wrapper for the RISC-V RDCYCLE pseudoinstruction.
///
/// # Returns
///
/// The value returned by the 'rdcycle' assembly instructions.
///

#[allow(dead_code)]
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
pub(crate) fn rdcycle() -> u32
{
    let mut x: u32;
    unsafe { asm!("rdcycle {x}", x = out(reg) x); }
    return x;
}
