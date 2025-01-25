//! The main interface to running enclave applications.
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

use std::sync::mpsc::{Receiver,  Sender};

use crate::{Error, Status};
use crate::attestation::Evidence;
use crate::builder::Builder;
use crate::device::{Device, KEYSTONE_NULL_DEVICE};
use crate::ecall::{CallID, Request, Response};
use crate::edge::{EdgeCall};
use crate::memory::uintptr;
use crate::ocall::{Listener};
use crate::internal::dispatcher::{Dispatcher};

/// An enclave instance
pub struct Enclave<'a> {
    /// Keystone pseudo-device
    device:     Option<Device>,
    /// Call dispatcher
    dispatcher: Dispatcher<'a>,
    /// Base address of the untrusted shared memory
    shrd_base:  uintptr,
    /// Size of the untrusted shared memory in bytes
    shrd_size:  uintptr,
    /// Hash of the enclave calculated by the builder (not secure)
    hash:       Vec<u8>,
}

impl <'a>Enclave<'a> {

    /// Create a new enclave.
    ///
    /// The created enclave is uninitialized. It must initialized with an
    /// application by calling the Enclave.build() function before it can be
    /// used.
    ///
    /// # Inputs
    ///
    /// * 'device_path' is a file path to the enclave device. Alternatively,
    ///    Device::KEYSTONE_NULL_DEVICE can be used to create a enclave
    ///    without a device, e.g., for simulation.
    ///
    /// # Returns
    ///
    /// A Result containing the enclave or an error code.
    ///

    pub fn new(device_path: &str) -> Result<Self, Error> {

        let device =
            if device_path == KEYSTONE_NULL_DEVICE {
                None
            }  else {
                Some(Device::new(device_path)?)
            };

        Ok(Self{device:     device,
                dispatcher: Dispatcher::new(),
                shrd_base:  0,
                shrd_size:  0,
                hash:       Vec::new()})
    }

    /// Initialize an enclave.
    ///
    /// Enclave application's memory is built and moved to the enclave.
    /// After this function has completed successfully, the enclave application
    /// can be started.
    ///
    /// # Inputs
    ///
    /// * 'builder' is a enclave Builder initialized with the enclave
    ///   application's parameters.
    ///
    /// # Returns
    ///
    /// A Result with Ok() in case the operation succeeds, or an error code
    /// otherwise.
    ///

    pub fn build(&mut self, builder: &Builder) -> Result<(), Error> {
        let device     =
            if self.device.is_some() {
                self.device.as_ref()
            } else {
                None
            };
        let output     = builder.build(device)?;
        self.shrd_base = output.shrd_base;
        self.shrd_size = output.shrd_size;
        self.hash      = output.hash;
        Ok(())
    }

    /// Retrieve a thread-safe handle to the enclave.
    ///
    /// The handle can be moved to another thread to perform enclave operations
    /// on a running enclave. Only one handle can be retrieved. After this, the
    /// function returns an error code.
    ///
    /// # Returns
    ///
    /// A Result containing the handle if the operation succeeded, or
    /// an Error code otherwise.
    ///

    pub fn handle(&mut self) -> Result<Handle, Error> {
        return self.dispatcher.handle();
    }

    /// Register new ocall listener.
    ///
    /// The listener will be notified on each ocall with the matching
    /// 'cid' when the enclave application is executed.
    ///
    /// # Inputs
    ///
    /// * 'cid' is the numeric call ID of the ocall. User-defined
    ///   ocalls must use call IDs between 0x0 and OCallID::LastUserID.
    ///
    /// * 'cb' is the listener object.
    ///
    /// # Returns
    ///
    /// A Result containing Ok() value if the registration succeeded, or
    /// an Error code otherwise.
    ///

    pub fn register_ocall(&mut self,
                          cid: u32,
                          cb: &'a dyn Listener)
                          -> Result<(), Error> {

        self.dispatcher.register_ocall(cid, cb)
    }

    /// Run the enclave.
    ///
    /// This call will block the current thread until the enclave terminates.
    ///
    /// # Returns
    ///
    /// A Result containing the value returned by the enclave in case the
    /// the enclave was executed successfully, or an error code othersize.
    ///

    pub fn run(&self) -> Result<u64, Error> {
        if self.device.is_none() {
            return Err(Error::BadState);
        }

        let rv = self.run_internal();
        // Release all threads waiting in ecalls.
        // Ecalls will return with Status::Done without completing the call.
        self.dispatcher.release_all();
        return rv;
    }

    fn run_internal(&self) -> Result<u64, Error> {

        if self.device.is_none() {
            return Err(Error::BadState);
        }

        let device = self.device.as_ref().unwrap();

        match device.run_enclave() {
            Ok(addr)   => return Ok(addr as u64),
            Err(error) => match error {
                Error::Pending => {
                    // Dispatch edge calls
                    let mut edge_call = unsafe {
                        &mut* std::ptr::with_exposed_provenance_mut::<EdgeCall>(self.shrd_base)
                    };

                    self.dispatcher.dispatch_ocall(&mut edge_call,
                                                   self.shrd_base,
                                                   self.shrd_size)?;
                },
                Error::Interrupted => {
                    // Nothing to do for now
                },
                _ => {
                    // A real error
                    return Err(error)
                },
            }
        }

        loop {
            match  device.resume_enclave() {
                Ok(addr)   => return Ok(addr as u64),
                Err(error) => match error {
                    Error::Pending => {
                        // Dispatch edge calls
                        let mut edge_call = unsafe {
                            &mut* std::ptr::with_exposed_provenance_mut::<EdgeCall>(self.shrd_base)
                        };

                        self.dispatcher.dispatch_ocall(&mut edge_call,
                                                       self.shrd_base,
                                                       self.shrd_size)?;
                    },
                    Error::Interrupted => {
                        // Nothing to do for now
                    },
                    _ => {
                        // A real error
                        return Err(error)
                    },
                }
            }
        }
    }


    /// Return hash value of enclave's presentation.
    ///
    /// The hash is computed when the enclave is built and matches to the
    /// integrity hash of the enclave computed by the Keystone Security Monitor.
    /// However, this value is computed in the host application. It MUST not be
    /// used as evidence on enclave integrity as it is not guaranteed to be
    /// securely computed. Enclave attestation features are designed for this
    /// purpose. Furthermore, it should not be used as a reference value for the
    /// integrity hash, unless computed in a secure (enough) environment.
    ///
    /// # Inputs
    ///
    /// * 'to' is a buffer where the hash should be copied to.
    ///
    /// # Returns
    ///
    /// A result containing the size of the hash in case of success and
    /// error value in case the operation failed.

    pub fn hash(&self, to: &mut [u8]) -> Result<usize, Error> {

        if self.hash.len() > to.len() {
            return Err(Error::BadArgument);
        }

        to[0 .. self.hash.len()].clone_from_slice(&self.hash[..]);
        return Ok(self.hash.len());
    }
}

/// An enclave handle
///
/// A handle is a thread-safe abstraction that can be used to perform enclave
/// operations while the enclave is running. Its primary use is to issue ecalls
/// from another thread.

pub struct Handle {
    tx: Sender<Request>,
    rx: Receiver<Response>,
}

impl Handle {

    pub(crate) fn new(tx: Sender<Request>, rx: Receiver<Response>)-> Self {
        Handle{tx: tx, rx: rx}
    }

    /// Make a ecall to the enclave using the handle.
    ///
    /// # Inputs
    ///
    /// * 'cid' is the numeric ID of the ecall. An ecall handler must have been
    ///   registered for the same ID in the enclave application.
    ///
    /// * 'params' is a byte buffer that will be copied to enclave application's
    ///    ecall handler as call arguments. This buffer must be heap allocated,
    ///    as its ownership is transferred to another thread handling the ecall.
    ///    The memory belonging to the buffer must not be accessed anymore.
    ///
    /// # Returns
    ///
    /// A result containing a pair of status code and optional byte buffer in
    /// case the call succeeds. The status code indicates the status of the
    /// ecall. The byte buffer, if present, contains the data returned by the
    /// ecall. In case of an error, only status code that describes the error
    /// is returned.
    ///

    pub fn ecall(&self,
                 cid: u32,
                 params: Option<Box<[u8]>>)
                 -> Result<(Status, Option<Box<[u8]>>), Status> {

        let req = Request::new(cid, params);
        if let Err(_) =  self.tx.send(req) {
            // Receiving end has been disconnected
            return Err(Status::Done);
        }

        /* Blocks */
        let mut res = match self.rx.recv() {
            Ok(res) => {
                res
            },
            Err(_) => {
                // Sending end has been disconnected
                return Err(Status::Done);
            }
        };

        /* Internal error */
        if res.cid() == CallID::as_u32(CallID::CallStatus) {
            return Err(res.status());
        }

        /* Invalid response */
        if res.cid() != cid {
            return Err(Status::InternalError);
        }

        return Ok((res.status(), res.data()));
    }

    /// Cause enclave's ecall handler to receive an interrupt.
    ///
    /// This function will not stop the enclave, but only cause enclave's ecall
    /// handler to return with Interrupted if it is currently blocked in a
    /// function such as serve() or wait(). Rest of the behavior is enclave
    /// dependent.
    ///


    pub fn stop(&self) {
        let req = Request::new(CallID::StopHandler as u32, None);
        // May fail if the other end has been disconnected
        match self.tx.send(req) {
            Ok(_)  => return,
            Err(_) => return,
        }
    }

    /// Challenge the enclave for attestation.
    ///
    /// In order to this call to succeed, the enclave must support and be
    /// currently processing ecalls, e.g., using functions such as serve()
    /// or wait().
    ///
    /// # Inputs
    ///
    /// * 'nonce' is a caller selected value included in the attestation report.
    ///   If selected randomly, this value can be used as a nonce to ensure
    ///   freshness of the report.
    ///
    /// # Returns
    ///
    /// A result containing attestation Evidence in case the call succeeds, or
    /// error in case the operation fails.

    pub fn attest(&self, nonce: &[u8]) -> Result<Evidence, Status> {
        let boxed = nonce.to_vec().into_boxed_slice(); /* Ugly */
        let res = self.ecall(CallID::as_u32(CallID::Attestation), Some(boxed))?;
        let status = res.0;
        match status {
            Status::Success => {
                match res.1 {
                    Some(buffer) => {
                        match Evidence::from_bytes(&buffer) {
                            Ok(evidence) => Ok(evidence),
                            _ => Err(status)
                        }
                    },
                    None => Err(status),
                }
            },
            _ => Err(status),
        }
    }
}
