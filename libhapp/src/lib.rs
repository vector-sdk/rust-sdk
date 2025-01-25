//! A crate for building Keystone host applications
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

extern crate std;

#[macro_use]
extern crate nix;
extern crate elf_rs;

mod binary;
mod edge;
mod internal;
mod memory;

/* Public interface */
pub mod attestation;
pub mod builder;
pub mod device;
pub mod ecall;
pub mod enclave;
pub mod ocall;

pub use enclave::Enclave as Enclave;
pub use ::edge::Status   as Status;
pub use ::edge::Error    as Error;
