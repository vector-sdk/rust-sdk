//! OCall API for calling host application from the enclave application
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

use crate::internal::syscall;

use crate::Status;
use edge::ocall::{RequestHeader, ResponseHeader};

pub use edge::ocall::{CallID};

/// Makes a call to the host application (ocall)
///
/// Call will be dispatched to a handler with the specified 'cid', if it is
/// registered in the host application. The buffer 'ibuf' will be copied into
/// the host application and any response will be copied to the enclave in the
/// buffer 'obuf'.
///
/// # Inputs
///
/// * 'cid'  is the call ID registered in the host application
/// * 'ibuf' is a byte buffer to send to the host application
/// * 'obuf' is a byte buffer where response from host application is written
///
/// # Returns
///
/// 'Status' indicating if the call succeeded.

#[deprecated]
pub fn ocall(cid: u64, in_buf: &[u8], out_buf: &mut [u8]) -> Status {
    let rv = syscall::ocall(cid, in_buf, out_buf);
    // TODO: Currently Eyrie always returns 0 or 1 for ocall:
    //return Status::from_usize(rv);
    return if rv == 0 { Status::Success } else { Status::Error };
}

#[deprecated]
pub fn ocall_inout(cid: u64, buf: &mut [u8], ilen: usize, olen: usize) -> Status {
    let rv = syscall::ocall_inout(cid, buf, ilen, olen);
    // TODO: Currently Eyrie always returns 0 or 1 for ocall:
    //return Status::from_usize(rv);
    return if rv == 0 { Status::Success } else { Status::Error };
}

/// Makes a call to the host application (ocall)
///
/// Call will be dispatched to a handler with the specified 'cid', if it is
/// registered in the host application. The buffer 'inbuf' will be copied into
/// the host application.
///
/// # Inputs
///
/// * 'cid'  is the call ID registered in the host application
/// * 'ibuf' is a byte buffer to send to the host application
///
/// # Returns
///
/// 'Status' indicating if the call succeeded.

#[deprecated]
pub fn ocall_out(cid: u64, in_buf: &[u8]) -> Status {
    let rv = syscall::ocall_out(cid, in_buf);
    // TODO: Currently Eyrie always returns 0 or 1 for ocall:
    //return Status::from_usize(rv);
    return if rv == 0 { Status::Success } else { Status::Error };
}


/// Makes a call to the host application (ocall).
///
/// Call will be dispatched to a handler with the specified 'cid', if it is
/// registered in the host application. Any response will be copied to the
/// enclave in the buffer 'obuf'.
///
/// # Inputs
///
/// * 'cid'  is the call ID registered in the host application
/// * 'obuf' is a byte buffer where response from host application is written
///
/// # Returns
///
/// 'Status' indicating if the call succeeded.

#[deprecated]
pub fn ocall_in(cid: u64, out_buf: &mut [u8]) -> Status {
    let rv = syscall::ocall_in(cid, out_buf);
    // TODO: Currently Eyrie always returns 0 or 1 for ocall:
    //return Status::from_usize(rv);
    return if rv == 0 { Status::Success } else { Status::Error };
}


/// Makes a call to the host application (ocall) with no input or
/// output buffers.
///
/// # Inputs
///
/// * 'cid'  is the call ID registered in the host application
///
/// # Returns
///
/// 'Status' indicating if the call succeeded.

#[deprecated]
pub fn ocall_cid(cid: u64) -> Status {
    let rv = syscall::ocall_cid(cid);
    // TODO: Currently Eyrie always returns 0 or 1 for ocall:
    //return Status::from_usize(rv);
    return if rv == 0 { Status::Success } else { Status::Error };
}

/// OCall structure for automatic management of request and response buffers
pub struct OCall<'a> {
    /// Buffer used for payload
    buffer:  &'a mut [u8],
    /// Request header
    req: RequestHeader,   // set before call
    /// Response header
    res: ResponseHeader,  // set after call
    /// Payload size
    req_len: usize,       // set before call
}

impl<'a> OCall<'a> {

    /// Size of the request header in bytes
    const REQ_HDR_SIZE: usize = core::mem::size_of::<RequestHeader>();
    /// Size of the response header in bytes
    const RES_HDR_SIZE: usize = core::mem::size_of::<ResponseHeader>();

    /* Larger of the two */
    /// Number of bytes guaranteed to hold either of the headers
    pub const HEADER_SIZE: usize = OCall::RES_HDR_SIZE;

    /// Prepare a new OCall structure
    ///
    /// # Input
    /// * 'buffer' is the memory area used for communication. It is reserved
    ///   for the use of the OCall for its lifetime and used to buffer both the
    ///   request and response payloads.
    ///

    pub fn prepare<'b: 'a>(buffer: &'b mut [u8]) -> Result<Self, Status> {
        let size = buffer.len();
        if size < OCall::HEADER_SIZE {
            return Err(Status::ShortBuffer);
        }

        Ok(Self{buffer:  buffer,
                req: RequestHeader::new(size),
                res: ResponseHeader::new(Status::Unknown, 0),
                req_len: 0})
    }

    /// Get request buffer as a mutable byte slice
    pub fn request<'b>(&'b mut self) -> &'b mut [u8] {
        &mut self.buffer[OCall::REQ_HDR_SIZE .. ]
    }

    /// Set request payload size
    pub fn request_length(&mut self, length: usize) -> bool {
        let total = length + OCall::REQ_HDR_SIZE;
        if total > self.buffer.len() {
            return false;
        }

        self.req_len = total;
        return true;
    }

    /// Get response buffer as a byte slice
    pub fn response<'b>(&'b self) -> &'b [u8] {
        let start = OCall::RES_HDR_SIZE;
        let end = start + self.res.size;
        let end = if end > self.buffer.len() {
            self.buffer.len()
        } else {
            end
        };
        &self.buffer[start .. end]
    }

    /// Get response payload size
    pub fn response_length(&self) -> usize {
        return self.res.size;
    }

    /// Execute an ocall
    ///
    /// # Input
    /// * 'cid' is the numeric call identifier
    /// * 'expect_data' if set to false is used to optimize calls that do not
    ///    allow payload data in response messages.
    ///

    pub fn call(&mut self, cid: u64, expect_data: bool) -> Result<Status, Status> {

        if !expect_data {
            self.req.max = 0;
        }

        let hdr = self.req.as_bytes();
        self.buffer[0 .. hdr.len()].copy_from_slice(hdr);
        let status = syscall::ocall_inout(cid, &mut self.buffer,
                                          self.req_len, self.req.max);

        if status != 0 {
            return Err(Status::SyscallFailed);
        }

        if !expect_data {
            return Ok(Status::Success);
        }

        let hdr = &self.buffer[0 .. OCall::RES_HDR_SIZE];
        self.res = match ResponseHeader::from_bytes(hdr) {
            Ok(res) => res,
            Err(_) => { return Err(Status::ShortBuffer); }
        };

        let total =  self.res.size + OCall::RES_HDR_SIZE;
        if total > self.buffer.len() {
            // TODO: basically the call succeeded, but not all input was
            //       received
            return Err(Status::ShortBuffer);
        }

        return Ok(Status::from_u32(self.res.status));
    }
}
