//! An API for Keystone data sealing within the enclave
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

extern crate core;

use crate::Status;
use crate::internal::syscall;

/// Retrieve enclave instance specific sealing key from the security monitor
///
/// After the call completes sucessfully, 'to' contains the sealing key
/// (the first 128 bytes) and a signature of the key (the next 64 bytes).
///
/// # Inputs
/// * 'to' is the buffer into which the report is written
///
/// # Returns
///
/// Ok(size) if the call succeeded, Err(Status) otherwise


pub fn get_sealing_key(ident: &[u8], to: &mut [u8]) -> Result<usize, Status> {
    if 0 != syscall::sealing_key(to, ident) {
        return Err(Status::Error);
    }

    return Ok(0 as usize);
}
