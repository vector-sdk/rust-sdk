//! Enclave memory debugging support
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

/* This code is only about debugging dynamic memory allocation in the enclave
 * at this point.
 */

use edge::alloc::{MemOp};

use crate::Status;
use crate::ocall::{OCall};

pub(crate) fn on_debug_memory(ctx: &mut OCall) -> Status {
    if let Ok(op) = MemOp::from_bytes(ctx.request()) {
        let label = if op.func == 0 { "alloc" } else { "free" };
        let addr  = op.addr;
        let size  = op.size;
        let align = op.align;
        println!("DbgMem: {} called on address {:#x} ({} {})",
                 label, addr, size, align);

        Status::Success
    } else {
        Status::Error
    }
}
