//! Keystone definitions for edge calls structures */
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

use std::os::raw::c_ulong;

/// Return header for ocalls
#[derive(Default, Copy, Clone)]
#[repr(C, packed)]
pub(crate)struct EdgeReturn {
    /// Status code
    pub(crate) status: c_ulong,
    /// Offset of the payload data from the beginning of
    /// the shared untrusted memory
    pub(crate) offset: usize,
    /// Size of the payload data in bytes
    pub(crate) size:   usize,
}

/// A header for ocalls
#[derive(Default, Copy, Clone)]
#[repr(C, packed)]
pub(crate) struct EdgeCall {
    /// Call identifier
    pub(crate) cid:    c_ulong,
    /// Offset of the payload data from the beginning of
    /// the untrusted shared memory
    pub(crate) offset: usize,
    /// Size of the payload data in bytes
    pub(crate) size:   usize,
    /// Memory for the call return information
    pub(crate) ret:    EdgeReturn,
}
