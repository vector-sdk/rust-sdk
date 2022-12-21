//! A 'no_std' compatible memory allocator based on the 'buddy_system_allocator'
//! and enclave runtime specific linker script. This version supports internal
//! memory debugging.
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

#[cfg(not(feature = "heap"))]
compile_error!("'alloc-debug.rs` depends on feature `heap`");

extern crate core;
extern crate alloc;
extern crate buddy_system_allocator;

use alloc::alloc::GlobalAlloc;
use alloc::alloc::Layout;
use core::arch::global_asm;
use core::ffi::c_void;
use core::ptr::NonNull;
use buddy_system_allocator::LockedHeap;

use edge::alloc::{FuncID, MemOp};

use crate::{Status, Error};
use crate::ocall::{CallID, OCall};
use crate::internal::{eapp_abort};

/// Buddy system allocator's order (for linked list)
const ORDER: usize = 32;

/* Heap related symbols */

global_asm!{include_str!("malloc_zone.S")}

/* Symbols for heap start and end positions */

extern "C" {
    /// The lowest byte available for dynamic memory management
    static __malloc_start: u8;
    /// The highest byte available for dynamic memory management
    static __malloc_zone_stop: u8;
}

static ALLOCATOR: LockedHeap<ORDER> = LockedHeap::empty();

/// Initializes heap memory allocator.
///
/// Must be called exactly once before the heap is used.

pub(crate) fn init() {
    unsafe {
        let heap_start = &__malloc_start as *const u8 as usize;
        let heap_end   = &__malloc_zone_stop as *const u8 as usize;
        ALLOCATOR.lock().add_to_heap(heap_start, heap_end);
    }
}

#[alloc_error_handler]
pub fn on_alloc_error(_layout: Layout) -> ! {
    eapp_abort(Error::OutOfMemory);
}

/* In case feature 'debug_memory' is set, then we add a wrapper to
 * the allocator that communicates allocated and deallocated memory
 * blocks to the host application.
 */

struct WrapperAllocator { }

#[global_allocator]
static WRAPPER_ALLOCATOR: WrapperAllocator = WrapperAllocator { };

unsafe impl GlobalAlloc for WrapperAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if let Ok(ptr) = ALLOCATOR.lock().alloc(layout) {
            let p = ptr.as_ptr();
            ocall_dbg_mem(FuncID::Alloc, p as *const c_void, layout);
            return p;
        }

        eapp_abort(Error::OutOfMemory);
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        ocall_dbg_mem(FuncID::Free, p as *const c_void, layout);
        ALLOCATOR.lock().dealloc(NonNull::new_unchecked(p), layout);
    }
}

fn ocall_dbg_mem(fid: FuncID, ptr: *const c_void, layout: Layout) -> Status {
    const SIZE: usize = core::mem::size_of::<MemOp>() + OCall::HEADER_SIZE;
    let mut buffer: [u8; SIZE] = [0; SIZE];
    if let Ok(mut ctx) = OCall::prepare(&mut buffer) {
        let req = ctx.request();
        let op  = MemOp::new(fid, ptr, layout);
        let buf = op.as_bytes();

        req[ .. buf.len()].clone_from_slice(buf);
        ctx.request_length(buf.len());
        return match ctx.call(CallID::DbgMemory as u64, false) {
            Ok(_)  => Status::Success,
            Err(status) => status,
        };
    }

    Status::Error
}
