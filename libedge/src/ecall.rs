//! ECall header definitions
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

/// Maximum number of ECall identifiers supported. Identifiers start from 0,
pub const ECALL_MAX_CID: usize = 16;
pub(crate) const MAX_ECALL: usize = 16;

/// Highest ECall identifier for user-defined calls
pub const ECALL_MAX_USER_CID: usize = MAX_ECALL - ECALL_RESERVED_CIDS;

/// Number of reserved ecall CIDS
pub(crate) const ECALL_RESERVED_CIDS: usize
    = CallID::MaxReservedID as usize - CallID::LastUserID as usize;

/// Call identifiers for reserved ECalls
pub enum CallID {
    /* Remember to adjust ECALL_RESERVED_CIDS accordingly */
    /// Highest allowed user-defined identifier
    LastUserID    = (ECALL_MAX_CID - 2) as isize, /* Not in use*/
    /// One past the highest valid identifier.
    MaxReservedID = (ECALL_MAX_CID) as isize, /* Not in use */
    /* Internal CIDs, no handler functions associated: */
    /// Request for the default attestation handler
    Attestation   = (ECALL_MAX_CID + 1) as isize,
    /// Request to stop the enclave
    StopHandler   = (ECALL_MAX_CID + 2) as isize, // Return from serve()
    /// Return simple status value to enclave
    CallStatus    = (ECALL_MAX_CID + 3) as isize, // Convey Status to enclave
}

impl CallID {
    pub fn as_u32(value: CallID) -> u32 {
        return value as u32;
    }
}

/// ECall (emulation) header
///
/// Both the request and response messages use the same header.
#[derive(Default, Copy, Clone)]
#[repr(C, packed)]
pub struct Header {
    /// Call identifier
    pub cid: u32,
    /// Call instance specific unique identifier
    pub uid: u32,
    /// Call return status
    pub sts: u32,
}

impl Header {

    /// Size of the header in bytes
    pub const SIZE: usize = core::mem::size_of::<Header>();

    /// Create a new header
    pub fn new(cid: u32, uid: u32, sts: u32) -> Self {
        Self{cid: cid, uid: uid, sts: sts}
    }

   /// Serialize header to raw byte format
    pub fn as_bytes(&self) -> &[u8] {
        // TODO: ugly!
        unsafe {
            core::slice::from_raw_parts((self as *const Self) as *const u8,
                                        core::mem::size_of::<Self>())
        }
    }

    /// Deserialize header from raw byte format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() == core::mem::size_of::<Self>() {
            // TODO: ugly!
            Ok(unsafe {*(bytes.as_ptr() as *const Self) })
        } else {
            Err(())
        }
    }
}
