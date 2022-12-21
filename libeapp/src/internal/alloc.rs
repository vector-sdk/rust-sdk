//! A 'no_std' compatible memory allocator based on the 'buddy_system_allocator'
//! and enclave runtime specific linker script.
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

#[cfg(not(feature = "heap"))]
compile_error!("'alloc.rs' depends on feature `heap`");

extern crate core;
extern crate alloc;
extern crate buddy_system_allocator;

use alloc::alloc::Layout;
use buddy_system_allocator::LockedHeap;
use core::arch::global_asm;

use crate::Error;
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

#[global_allocator]
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
