//! ECall API (emulation) for calling enclave application from host applications
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

// Emulation of ecalls by polling ocalls since Keystone Eyrie doesn't
// yet support real ecalls.

#[cfg(feature = "heap")]
extern crate alloc;
extern crate core;

#[cfg(feature = "heap_rt")]
use alloc::vec::Vec;

#[cfg(not(feature = "heap_rt"))]
use core::arch::global_asm;

use edge::ecall::{ECALL_MAX_CID, ECALL_MAX_USER_CID};
use edge::ecall::{Header};

pub use ::edge::ecall::CallID as CallID;

use crate::Status;
use crate::ocall::CallID as OCallID;
use crate::ocall::OCall;
use crate::attestation::attest;

/// ECall structure for automatic management of request and response buffers
///
/// An ecall is emulated with a pair of ocalls.

pub struct ECall<'a, 's1: 'a, 's2: 'a> {
    /// OCall structure for ecall poll
    req: &'a OCall<'s1>,
    /// OCall structure for ecall return
    res: &'a mut OCall<'s2>,
    /// Call header
    hdr: Header,
}

/// A listener for receiving user-defined ecalls
pub trait Listener {

    /// Callback for handling user-defined ecalls
    ///
    /// # Input
    /// * 'ctx' is the ecall structure for this call
    /// * 'req' is the ecall request payload as a byte slice
    ///
    /// # Return
    ///
    /// Call status. Any status except Status::Success will cause
    /// the server to return after handling the call.

    fn on_ecall(&self, ctx: &mut ECall, req: &[u8]) -> Status;
}

impl<'a, 's1: 'a, 's2: 'a> ECall<'a, 's1, 's2> {

    /// Size of ECall header in in bytes
    pub const HEADER_SIZE: usize = OCall::HEADER_SIZE + Header::SIZE;

    /// Create a new ECall structure from two existing OCall structures
    ///
    /// Only for internal use of the ecall dispatcher!

    fn prepare(cid: u32,
               uid: u32,
               req: &'a OCall<'s1>,
               res: &'a mut OCall<'s2>) -> Result<Self, Status> {

        if req.response_length() < Header::SIZE {
            return Err(Status::ShortBuffer);
        }

        if res.request().len() < Header::SIZE {
            return Err(Status::ShortBuffer);
        }

        // At least ECall header will be sent
        res.request_length(Header::SIZE);
        Ok(ECall{req: req, res: res, hdr: Header::new(cid, uid, 0)})
    }

    /// Get call identifier
    pub fn cid(&self) -> u32 {
        self.hdr.cid
    }

    // Set call status
    fn status(&mut self, status: Status) {
        self.hdr.sts = status as u32;
    }

    /// Get request payload data as a byte slice
    pub fn request<'b>(&'b self) -> &'b [u8] {
        let data = self.req.response();
        &data[Header::SIZE ..]
    }

    /// Get request payload length
    pub fn request_length(&self) -> usize {
        self.req.response_length() - Header::SIZE
    }

    /// Get response payload buffer as a mutable byte slice
    pub fn response<'b>(&'b mut self) -> &'b mut [u8] {
        let data = self.res.request();
        &mut data[Header::SIZE .. ]
    }

    /// Set response payload length
    pub fn response_length(&mut self, length: usize) -> bool {
        self.res.request_length(length + Header::SIZE)
    }

    /// Execute call
    fn send(&mut self) -> Status {
        /* In case of an error, only send the header */
        if self.hdr.sts != Status::as_u32(Status::Success) {
            self.res.request_length(Header::SIZE);
        }

        let req = self.res.request();
        let hdr = self.hdr.as_bytes();

        if req.len() < hdr.len() {
            return Status::ShortBuffer;
        }

        req[ .. hdr.len()].copy_from_slice(hdr);
        return match self.res.call(OCallID::ECallReturn as u64, true) {
            Ok(_)       => Status::Success,
            Err(status) => status,
        };
    }
}

#[cfg(feature = "heap_rt")]
struct Buffer {
    data: Vec<u8>,
}

#[cfg(feature = "heap_rt")]
impl Buffer {

    fn new() -> Self {
        Self{data: Vec::new()}
    }

    fn resize(&mut self, size: usize) -> bool {
        let total = ECall::HEADER_SIZE + size;
        if total <= self.data.len() {
            self.data.truncate(total);
            return true;
        }

        let more = total - self.data.len();
        match self.data.try_reserve_exact(more) {
            Ok(_)  => {
                self.data.resize(total, 0);
                true
            }
            Err(_) => false
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..]
    }
}

#[cfg(not(feature = "heap_rt"))]
struct Buffer {
    data: &'static mut [u8],
    size: usize,
}

#[cfg(not(feature = "heap_rt"))]
impl Buffer {

    fn new(data: &'static mut [u8]) -> Self {
        let size = data.len();
        Self{data: data, size: size}
    }

    fn resize(&mut self, size: usize) -> bool {
        let total = ECall::HEADER_SIZE + size;
        if total > self.data.len() {
            return false;
        }

        self.size = total;
        return true;
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[.. self.size]
    }
}

/// Dispatcher for ecalls
///
/// Simply a table of listeners.
struct Dispatcher<'a> {
    /// Dispatch table from call identifier to Listener
    table: [Option<&'a dyn Listener>; ECALL_MAX_CID],
}

impl<'a> Dispatcher<'a> {

    fn new() -> Self {
        Self{table: [None; ECALL_MAX_CID]}
    }

    fn get(&self, i: usize) -> Option<&'a dyn Listener> {
        if i >= self.table.len() {
            return None;
        }

        return self.table[i];
    }

    fn set(&mut self, i: usize, cb: &'a dyn Listener) -> bool {
        if i >= self.table.len() {
            return false;
        }

        self.table[i] = Some(cb);
        return true;
    }
}

/// Server for listening and handling ecalls
///
/// The server can handle a single ecall at the time
pub struct Server<'a> {
    /// Buffer for incoming ecalls
    ibuf:       Buffer,
    /// Buffer for outcoming eall
    obuf:       Buffer,
    /// Dispatcher for routing calls to listeners
    dispatcher: Dispatcher<'a>,
}

impl<'a> Server<'a> {

    /// Create a new ecall server
    pub fn new() -> Self {
        Self{ibuf: Server::input_buffer(),
             obuf: Server::output_buffer(),
             dispatcher: Dispatcher::new()}
    }

    /// Set maximum reqeust size and reserve memory for input data
    ///
    /// # Input
    /// * 'size' is the maximum allowed input in bytes. This doesn't
    ///   include the ecall headers, but only the payload.
    ///
    /// # Return
    ///
    /// 'true' if the buffer was reserved, 'false otherwise

    pub fn max_input_size(&mut self, size: usize) -> bool {
        self.ibuf.resize(size)
    }

    /// Set maximum response size and reserve memory for output data
    ///
    /// # Input
    /// * 'size' is the maximum allowed output in bytes. This doesn't
    ///   include the ecall headers, but only the payload.
    ///
    /// # Return
    ///
    /// 'true' if the buffer was reserved, 'false otherwise

    pub fn max_output_size(&mut self, size: usize) -> bool {
        self.obuf.resize(size)
    }

    /// Register a listener for specific call identifier
    ///
    /// # Input
    /// * 'cid' is the call identifier
    /// * 'cb' is a reference to an object implementing the Listener trait
    ///
    /// # Return
    ///
    /// 'tue' in case the listener was added, 'falseä otherwise

    pub fn register(&mut self, cid: u32, cb: &'a dyn Listener) -> bool {
        let id = cid as usize;
        if id >= ECALL_MAX_USER_CID {
            return false;
        }

        self.dispatcher.set(id, cb)
    }

    /* Emulate or serve single ecall */
    fn wait_internal(&mut self) -> Status {
        let inbuf  = self.ibuf.as_mut_slice();
        let outbuf = self.obuf.as_mut_slice();

        if inbuf.len() < ECall::HEADER_SIZE {
            return Status::ShortBuffer;
        }

        if outbuf.len() < ECall::HEADER_SIZE {
            return Status::ShortBuffer;
        }

        let mut poll_ctx = match OCall::prepare(inbuf) {
            Ok(ctx)     => ctx,
            Err(status) => {
                return status;
            }
        };

        poll_ctx.request_length(0);

        let status = match poll_ctx.call(OCallID::ECallPoll as u64, true) {
            Ok(status)  => status,
            Err(status) => {
                return status;
            }
        };

        let req_buf = poll_ctx.response();
        let req_len = poll_ctx.response_length();

        if  req_len > req_buf.len() || req_len < Header::SIZE {
            return Status::ShortBuffer;
        }

        if req_len != req_buf.len() {
            return Status::ShortBuffer;
        }

        let hdr = match Header::from_bytes(&req_buf[0 .. Header::SIZE]) {
            Ok(hdr) => hdr,
            Err(_) => { return Status::ShortBuffer; },
        };

        let cid = hdr.cid;
        let uid = hdr.uid;
//        let sts = hdr.sts;

        /* Done, No pending calls, etc. */
        if cid == CallID::as_u32(CallID::CallStatus) {
            return status;
        }

        /* Request stop (ecall) */
        if cid == CallID::as_u32(CallID::StopHandler) {
            return Status::Interrupted;
        }

        /* OCall for ECall's return call */
        let mut rtrn_ctx = match OCall::prepare(outbuf) {
            Ok(ctx)     => ctx,
            Err(status) => {
                return status;
            }
        };

        /* ECall context */
        let mut ctx = match ECall::prepare(cid, uid, &poll_ctx, &mut rtrn_ctx) {
            Ok(ctx)     => ctx,
            Err(status) => {
                return status;
            }
        };

        let req = &(ctx.req.response())[Header::SIZE ..];
        let status = dispatch_internal(cid, &mut ctx, &req);
        let status =
            if status == Status::BadCallID {
                if let Some(callback) = self.dispatcher.get(cid as usize) {
                    callback.on_ecall(&mut ctx, &req)
                } else {
                    Status::BadCallID
                }
            } else {
                status
            };

        if status != Status::Done {
            ctx.status(status);
            return ctx.send();
        }

        /* The ecall callback asked to return from the ecall-handler's serve call */
        ctx.status(Status::Success);
        let retval = ctx.send();
        return if retval == Status::Success {
            Status::Done
        } else {
            retval
        }
    }

    /// Serve next waiting ecall if any are pending
    pub fn wait(&mut self) -> Status {
        let status = self.wait_internal();
        return status;
    }

    /// Serve ecalls in a loop
    ///
    /// Blocks until one of the listener return status other than
    /// Status::Success.

    pub fn serve(&mut self) -> Status {
        let mut status = Status::Success;
        while status == Status::Success || status == Status::NoPending {
            /* TODO: sleep => leads to busy wait. How to handle  ? */
            status = self.wait();
        }

        return status;
    }
}

// Dispatch internally handled ecalls
fn dispatch_internal(cid: u32, ctx: &mut ECall, req: &[u8]) -> Status {
    if cid == CallID::as_u32(CallID::Attestation) {
        let nonce  = req;
        let report = ctx.response();
        match attest(nonce, report) {
            Ok(length) => {
                if !ctx.response_length(length) {
                    return Status::ShortBuffer;
                }
                return Status::Success;
            },
            Err(status) => {
                return status
            }
        }
    }

    Status::BadCallID
}

/* Define static ecall input and output buffers (link-time) */

#[cfg(not(feature = "heap_rt"))]
global_asm!{include_str!("internal/ecall_zone.S")}

#[cfg(not(feature = "heap_rt"))]
impl<'a> Server<'a> {

    fn input_buffer() -> Buffer {
        extern "C" {
            static mut __ecall_inbuf_start: u8;
            static __ecall_inbuf_end: u8;
        }

        let size = unsafe {
            (&__ecall_inbuf_end as *const u8) as usize
                - (&__ecall_inbuf_start as *const u8) as usize
        };

        let buffer = unsafe {
            core::slice::from_raw_parts_mut(&mut __ecall_inbuf_start, size)
        };

        Buffer::new(buffer)
    }

    fn output_buffer() -> Buffer {
        extern "C" {
            static mut __ecall_outbuf_start: u8;
            static __ecall_outbuf_end: u8;
        }

        let size = unsafe {
            (&__ecall_outbuf_end as *const u8) as usize
                - (&__ecall_outbuf_start as *const u8) as usize
        };

        let buffer = unsafe {
            core::slice::from_raw_parts_mut(&mut __ecall_outbuf_start, size)
        };
        Buffer::new(buffer)
    }
}

// If we have heap, the buffers are allocated dynamically
#[cfg(feature = "heap_rt")]
impl<'a> Server<'a> {

    fn input_buffer() -> Buffer {
        Buffer::new()
    }

    fn output_buffer() -> Buffer {
        Buffer::new()
    }
}
