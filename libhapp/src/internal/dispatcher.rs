//! OCall dispatcher
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

use std::os::raw::c_ulong;

use edge::ocall::{EDGE_SYSCALL, MAX_OCALL};

use crate::{Error, Status};
#[cfg(feature = "debug_memory")]
use crate::internal::alloc;
use crate::ecall::Emulator;
use crate::edge::EdgeCall;
use crate::enclave::Handle;
use crate::memory::uintptr;
use crate::ocall::{Listener, OCall};
#[cfg(feature = "debug_memory")]
use crate::ocall::{CallID};

pub(crate) struct Dispatcher<'a> {
    /// Emulator for the ecalls
    ecall: Emulator,
    /// A table mapping call indetifiers to Listeners
    table: [Option<&'a dyn Listener>; MAX_OCALL as usize]
}

impl <'a>Dispatcher<'a> {

    pub(crate) fn new() -> Self {
        Self{ecall: Emulator::new(),
             table: [None; MAX_OCALL as usize]}
    }

    pub(crate) fn handle(&mut self) -> Result<Handle, Error> {
        return self.ecall.handle();
    }

    #[cfg(not(feature = "debug_memory"))]
    fn dispatch_internal(&self, cid: u32, ctx: &mut OCall) -> Status {
        if cid == EDGE_SYSCALL {
            // TODO: not supported
            return Status::SyscallFailed
        }

        self.ecall.on_ocall(ctx)
    }

    #[cfg(feature = "debug_memory")]
    fn dispatch_internal(&self, cid: u32, ctx: &mut OCall) -> Status {
        if cid == EDGE_SYSCALL {
            // TODO: not supported
            return Status::SyscallFailed
        }

        if cid == CallID::DbgMemory as u32 {
            return alloc::on_debug_memory(ctx);
        }

        self.ecall.on_ocall(ctx)
    }

    pub(crate) fn dispatch_ocall(&self,
                                 edge_call: &mut EdgeCall,
                                 shrd_base: uintptr,
                                 shrd_size: usize)
                                 -> Result<(), Error> {

        if edge_call.offset > shrd_size {
            edge_call.ret.status = Status::BadOffset as c_ulong;
            return Ok(()); // Enclave handles error
        }

        if shrd_size - edge_call.offset < edge_call.size {
            edge_call.ret.status = Status::BadOffset as c_ulong;
            return Ok(()); // Enclave handles error
        }

        assert!(edge_call.offset >= std::mem::size_of::<EdgeCall>());

        let cid = edge_call.cid as u32;
        let mut ctx  = OCall::wrap(edge_call, shrd_base, shrd_size);

        /* ECall emulation and some other internally implemented
         * call handlers are not in the listener list, mostly because
         * of Rust's borrowing rules and the requirement for the listener
         * addresses. */
        let status = self.dispatch_internal(cid, &mut ctx);
        if status != Status::BadCallID {
            ctx.finalize(status);
            edge_call.ret.status = status as c_ulong;
            return Ok(());
        }

        if cid as usize >= self.table.len() {
            ctx.finalize(Status::BadCallID);
            edge_call.ret.status = Status::BadCallID as c_ulong;
            return Ok(()); // Enclave handles error
        }

        let listener = self.table[cid as usize];
        if listener.is_none() {
            ctx.finalize(Status::BadCallID);
            edge_call.ret.status = Status::BadCallID as c_ulong;
            return Ok(()); // Enclave handles error
        }

        let status = listener.unwrap().on_ocall(&mut ctx);
        ctx.finalize(status);
        edge_call.ret.status = status as c_ulong;
        Ok(())
    }

    pub(crate) fn register_ocall(&mut self,
                                 cid: u32,
                                 cb:  &'a dyn Listener)
                                 -> Result<(), Error> {

        if cid as usize >= self.table.len() {
            return Err(Error::BadArgument);
        }

        self.table[cid as usize] = Some(cb);
        Ok(())
    }

    // Releases all threads that are blocked in the ecall handler
    pub(crate) fn release_all(&self) {
        self.ecall.release_all()
    }
}
