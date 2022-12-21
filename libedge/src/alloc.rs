//! Defintions for SDK's internal memory debugging support
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

extern crate alloc;
extern crate core;

use alloc::alloc::Layout;
use core::ffi::c_void;

/// Memory operation type
pub enum FuncID {
    /// Memory allocation
    Alloc = 0x00,
    /// Memory deallocation
    Free  = 0x01,
}

/// Memory operation descriptor
#[derive(Default, Copy, Clone)]
#[repr(C, packed)]
pub struct MemOp {
    /// Operation type
    pub func:  u16,
    /// Address of the memory block
    pub addr:  usize,
    /// Size of the memory block
    pub size:  usize,
    /// Word-aligment of the memoty block
    pub align: usize,
}

impl MemOp {
    /// Create a new memory operation descriptor
    pub fn new(func: FuncID, ptr: *const c_void, layout: Layout) -> Self {
        Self{func: func as u16,
             addr: ptr as usize,
             size: layout.size(),
             align: layout.align()}
    }

    /// Serialize as raq memory bytes
    pub fn as_bytes(&self) -> &[u8] {
        // TODO: ugly!
        unsafe {
            core::slice::from_raw_parts((self as *const Self) as *const u8,
                                        core::mem::size_of::<Self>())
        }
    }

    /// Deserialize ffrom raw memory bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() ==core::mem::size_of::<Self>() {
            // TODO: ugly!
            Ok(unsafe { *(bytes.as_ptr() as *const Self) })
        } else {
            Err(())
        }
    }
}
