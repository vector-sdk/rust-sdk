//! A Rust library for writing enclave applications for the Keystone Enclave.
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

#![feature(alloc_error_handler)]
#![no_std]
#![no_main]

extern crate core;

mod internal;

use core::panic::PanicInfo;

use crate::internal::{eapp_abort};
use crate::internal::syscall;

/* Public interface */
pub mod attestation;
pub mod ecall;
pub mod ocall;
pub mod sealing;
pub use eapp_macros::{eapp_entry};

pub use ::edge::Status as Status;
pub use ::edge::Error  as Error;

/// Return from the enclave application and terminate the enclave.
///
/// # Inputs
///
/// * 'value' is a return value submitted to the thread that started the
///   enclave application at the host.
///
/// # Returns
///
/// This function never returns

pub fn eapp_return(value : u64) -> ! {
    syscall::exit(value);
}

/// Entry point to enclave application's Rust "runtime"
#[no_mangle]
extern "C" fn _start() -> ! {
    extern "Rust" {
        // Declaration for the user supplied function marked as the
        // enclave application entry point with #[eapp_entry].
        // The name is enforced by the macro.
        fn _eapp_entry() -> u64;
    }

    /* Runtime initialization */
    crate::internal::init();

    // Call user defined enclave application entry point:
    let rv: u64 = unsafe { _eapp_entry() };
    eapp_return(rv);
}

/* Panic handler: aborts the enclave */
#[no_mangle]
#[panic_handler]
fn on_panic(_info: &PanicInfo) -> ! {
   eapp_abort(Error::Panic);
}
