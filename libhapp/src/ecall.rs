//! An API to make (emulated) ecalls to the enclave application
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

use std::cell::RefCell;
use std::sync::mpsc::{channel, Receiver, Sender};

#[cfg(all(feature = "ecall_busywait", feature = "ecall_timeout"))]
compile_error!("features `ecall_busywait` and `ecall_timeout` are mutually exclusive");

#[cfg(feature = "ecall_busywait")]
use std::sync::mpsc::TryRecvError;

#[cfg(feature = "ecall_timeout")]
use std::sync::mpsc::RecvTimeoutError;
#[cfg(feature = "ecall_timeout")]
use std::time::Duration;

use rand::rngs::OsRng;
use rand::RngCore;

use edge::ecall::{Header};
pub use edge::ecall::{CallID};

use crate::{Error, Status};
use crate::enclave::Handle;
use crate::ocall::{Listener, OCall};
use crate::ocall::CallID as OCallID;

#[cfg(feature = "ecall_timeout")]
/* ECall poll will return to enclave after this many milliseconds, if there
 * are no pending ecalls: */
const ECALL_POLL_MAX_WAIT_MS: u64 = 500;

/* Emulated ecall request */
pub(crate) struct Request {
    hdr:  Header,
    data: Option<Box<[u8]>>, /* Input parameters (must be in heap currently) */
}

/* Emulated ecall response */
pub(crate) struct Response {
    hdr:  Header,
    data: Option<Box<[u8]>>, /* Output value (must be in heap currently) */
}

impl Request {

    pub(crate) fn new(cid: u32, data: Option<Box<[u8]>>) -> Self {
        let uid = OsRng::default().next_u32();
        Self{hdr: Header::new(cid, uid, 0), data: data}
    }
}

impl Response {

    fn new(cid: u32, sts: Status, data: Option<Box<[u8]>>) -> Self {
        Self{hdr: Header::new(cid, 0, Status::as_u32(sts)), data: data}
    }

    pub(crate) fn cid(&self) -> u32 {
        self.hdr.cid
    }

    pub(crate) fn status(&self) -> Status {
        Status::from_u32(self.hdr.sts)
    }

    pub(crate) fn data(&mut self) -> Option<Box<[u8]>> {
        self.data.take()
    }
}

// Internal struct needed for dropping the channels before the enclave
struct Channels {
    rx:     Receiver<Request>,
    tx:     Sender<Response>,
}

pub(crate) struct Emulator {
    channels: RefCell<Option<Channels>>,
    task:     RefCell<Option<Request>>,
    handle:   Option<Handle>,
}

impl Listener for Emulator {

    fn on_ocall(&self, ctx: &mut OCall) -> Status {
        let cid = ctx.cid();
        if cid == OCallID::ECallPoll as u32 {
            self.on_poll(ctx)
        } else if cid == OCallID::ECallReturn as u32 {
            self.on_return(ctx)
        } else {
            Status::BadCallID
        }
    }
}

fn return_status(ctx: &mut OCall, status: Status) -> Status {
    let res = ctx.response();
    if res.len() < Header::SIZE {
        return Status::ShortBuffer;
    }

    let hdr = Header::new(CallID::as_u32(CallID::CallStatus), 0,
                          Status::as_u32(status));
    res[.. Header::SIZE].clone_from_slice(hdr.as_bytes());
    ctx.response_length(Header::SIZE);
    return Status::Success;
}

#[cfg(not(any(feature = "ecall_busywait", feature = "ecall_timeout")))]
fn try_recv(rx: &Receiver<Request>) -> Result<Request, Status> {
    match rx.recv() {
        Ok(req) => Ok(req),
        Err(_)  =>
        // No more ecalls can be done, as the handle has been
        // deallocated: request enclave's ecall handler to stop:
            Err(Status::Done)
    }
}

#[cfg(feature = "ecall_busywait")]
fn try_recv(rx: &Receiver<Request>) -> Result<Request, Status> {
    match rx.try_recv() {
        Ok(req) => Ok(req),
        Err(status)  => match status {
            TryRecvError::Empty => {
                Err(Status::NoPending)
            },
            TryRecvError::Disconnected => {
                // No more ecalls can be done, as the handle has been
                // deallocated: request enclave's ecall handler to stop:
                Err(Status::Done)
            }
        }
    }
}

#[cfg(feature = "ecall_timeout")]
fn try_recv(rx: &Receiver<Request>) -> Result<Request, Status> {
    match rx.recv_timeout(Duration::from_millis(ECALL_POLL_MAX_WAIT_MS)) {
        Ok(req) => Ok(req),
        Err(status)  => match status {
            RecvTimeoutError::Timeout => {
                Err(Status::NoPending)
            },
            RecvTimeoutError::Disconnected => {
                // No more ecalls can be done, as the handle has been
                // deallocated: request enclave's ecall handler to stop:
                Err(Status::Done)
            }
        }
    }
}

impl Emulator {
    pub(crate) fn new() -> Self {
        let (etx, erx): (Sender<Request>, Receiver<Request>)   = channel();
        let (otx, orx): (Sender<Response>, Receiver<Response>) = channel();
        let handle  = Handle::new(etx, orx);
        Self{channels: RefCell::new(Some(Channels{rx: erx, tx: otx})),
             task:     RefCell::new(None),
             handle:   Some(handle)}
    }

    pub(crate) fn handle(&mut self) -> Result<Handle, Error> {
        let current = self.handle.take();
        match current {
            Some(value) => Ok(value),
            None         => Err(Error::BadState),
        }
    }

    fn on_poll(&self, ctx: &mut OCall) -> Status {

        if self.task.borrow().is_some() {
            /* TODO: enclave did not call ECALL_RETURN for some reason
             *       -> terminate and clean current task! */
            return Status::Error;
        }

        let chan_ref = self.channels.borrow();
        let channels = if let Some(channels) = chan_ref.as_ref() {
            channels
        } else {
            return return_status(ctx, Status::Done);
        };

        let req = match try_recv(&channels.rx) {
            Ok(req) => req,
            Err(status) => {
                return return_status(ctx, status);
            }
        };

        let req_len = match req.data {
            Some(ref bytes) => bytes.len() as usize,
            None => 0,
        };

        let res = ctx.response();
        if res.len() < req_len + Header::SIZE {
            return return_status(ctx, Status::ShortBuffer);
        }

        res[ .. Header::SIZE].clone_from_slice(req.hdr.as_bytes());

        if let Some(ref bytes) = req.data {
            let offset = Header::SIZE;
            res[offset .. offset + bytes.len()].clone_from_slice(bytes);
        }

        ctx.response_length(req_len +  Header::SIZE);
        self.task.replace(Some(req));
        return Status::Success;
    }

    fn on_return(&self, ctx: &mut OCall) -> Status {
        let chan_ref = self.channels.borrow();
        let channels = if let Some(channels) = chan_ref.as_ref() {
            channels
        } else {
            return return_status(ctx, Status::Done);
        };

        if !self.task.borrow().is_some() {
            let res = Response::new(CallID::as_u32(CallID::CallStatus),
                                    Status::InternalError, None);
            if let Err(_) = channels.tx.send(res) {
                // Receiver has already been deallocated,
                // no more ecalls will follow
            }

            return_status(ctx, Status::Error);
            return Status::Error;
        }

        /* Not a full header: */
        let req = ctx.request();
        if req.len() < Header::SIZE {
            let res = Response::new(CallID::as_u32(CallID::CallStatus),
                                    Status::InternalError, None);
            if let Err(_) = channels.tx.send(res) {
                // Receiver has already been deallocated,
                // no more ecalls will follow
            }

            return_status(ctx, Status::BadOffset);
            return Status::BadOffset;
        }

        let hdr = Header::from_bytes(&req[ .. Header::SIZE]).unwrap();

        let current = self.task.replace(None);
        let valid = match current {
            Some(ref req) => req.hdr.cid == hdr.cid && req.hdr.uid == hdr.uid,
            None          => false,
        };

        match valid {
            true => {
                let data = if req.len() != Header::SIZE {
                    Some((req[Header::SIZE .. req.len()]).to_vec().into_boxed_slice())
                } else {
                    None
                };

                let res = Response::new(hdr.cid, Status::from_u32(hdr.sts), data);
                if let Err(_) = channels.tx.send(res) {
                    // Receiver has already been deallocated,
                    // no more ecalls will follow
                    // todo: ENCLAVE CANNOT RECEIVE THIS?
                    return return_status(ctx, Status::Done);
                }
                return return_status(ctx, Status::Success);
            },
            false => {
                let res = Response::new(hdr.cid, Status::InternalError, None);
                if let Err(_) = channels.tx.send(res) {
                    // Receiver has already been deallocated,
                    // no more ecalls will follow
                }

                return_status(ctx, Status::Error);
                return Status::Error;
            }
        }
    }

    // Releases all threads that are blocked in the ecall handler
    pub(crate) fn release_all(&self) {
        if let Some(_) =  self.channels.replace(None) {
            // Drop the channels, causing all current and future
            // ecall request to fail with Status::Done
        }
    }
}
