//! OCall API for serving ocalls from the enclave application
///
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

use edge::ocall::{RequestHeader, ResponseHeader};
pub use edge::ocall::CallID;

use crate::Status;
use crate::edge::EdgeCall;
use crate::memory::uintptr;

/// Listener for ocalls from the enclave
pub trait Listener {

    /// This callback is called on each ocall dispatched to the listener
    ///
    /// # Input
    /// * 'ctx' is the call contenxt describing the call
    ///
    /// # Return
    ///
    /// Status value sent to the enclave application

    fn on_ocall(&self, ctx: &mut OCall) -> Status;
}

/// OCall context
pub struct OCall<'a> {
    /// Keystone edge call context
    ctx:  &'a mut EdgeCall,
    /// Untrusted shared memory available for the call
    buffer: &'a mut [u8],   /* Untrusted shared memory */
    /// Call request header
    req: RequestHeader,
    /// Call response header
    res: ResponseHeader,
    /// Request payload length (without hedears) in bytes
    req_len: usize,
}

impl<'a> OCall<'a> {

    /// Number of bytes needed for the OCall header
    pub const HEADER_SIZE: usize = ResponseHeader::SIZE; /* Larger header */

    /// Wrap an edge call as Ocall
    pub(crate) fn wrap(ctx:  &'a mut EdgeCall,
                       base: uintptr,
                       size: usize)
                       -> Self {

        ctx.ret.size = 0;

        let shared = unsafe {
            let ptr = std::ptr::from_exposed_addr_mut::<u8>(base);
            let ptr = ptr.add(ctx.offset);
            std::slice::from_raw_parts_mut(ptr, size)
        };

        let mut req = RequestHeader::from_bytes(&shared[ .. RequestHeader::SIZE]).unwrap();
        let req_len = ctx.size - core::mem::size_of::<RequestHeader>();
        /* Enclave doesn't know size of the shared area, so we must also check that: */
        req.max = if req.max > size { size } else { req.max };

        Self{ctx: ctx, buffer: shared,
             req: req, res: ResponseHeader::empty(),
             req_len: req_len}
    }

    /// Get call identifier
    pub fn cid(&self) -> u32 {
        return self.ctx.cid as u32;
    }

    /// Get request payload as a byte slice
    ///
    /// The slice belongs to the untrusted shared memory
    pub fn request<'b>(&'b self) -> &'b [u8] {
        &self.buffer[RequestHeader::SIZE .. RequestHeader::SIZE + self.req_len]
    }

    /// Get request length in bytes
    pub fn request_length(&self) -> usize {
        self.req_len
    }

    /// Get mutable byte slice of the respose buffer
    ///
    /// The slice belongs to the untrusted shared memory
    pub fn response<'b>(&'b mut self) -> &'b mut [u8] {
        &mut self.buffer[ResponseHeader::SIZE .. self.req.max]
    }

    /// Set length of the response payload in bytes
    ///
    /// If not set, payload size is zero bytes
    pub fn response_length(&mut self, length: usize) -> bool {
        let total = length + ResponseHeader::SIZE;
        if total > self.req.max {
            return false;
        }

        self.res.size = length;
        return true;
    }

    /// Finalize call response in the shared memory
    pub(crate) fn finalize(&mut self, status: Status) {
        self.res.status = Status::as_u32(status);
        self.buffer[ .. ResponseHeader::SIZE].clone_from_slice(self.res.as_bytes());
        self.ctx.ret.offset = std::mem::size_of::<EdgeCall>();
        self.ctx.ret.size   = self.res.size + core::mem::size_of::<ResponseHeader>();
    }
}
