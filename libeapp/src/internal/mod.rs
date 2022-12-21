//! Internal interface for calling runtime services
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

extern crate core;

use crate::Error;

pub(crate) mod utils;
pub(crate) mod syscall;

// Select between the normal and the debug memory allocator
#[cfg_attr(all(feature = "heap", feature = "debug_memory"), path = "alloc-debug.rs")]
#[cfg(feature = "heap")]
pub(crate) mod alloc;

/// Internal helper function for returning Errors without having to
/// convert them to u64 in each location
pub(crate) fn eapp_abort(e: Error) -> ! {
    super::eapp_return(e as u64);
}

#[cfg(feature = "heap")]
pub(crate) fn init_heap() {
    alloc::init();
}

#[cfg(not(feature = "heap"))]
pub(crate) fn init_heap() {
    // Do nothing
}

/// Runtime specific initializations. Called from _start, before the enclave
/// application's entry point is executed.
pub(crate) fn init() {
    init_heap();
}
