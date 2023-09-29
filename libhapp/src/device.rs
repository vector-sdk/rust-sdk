//! Keystone pseudo-device API
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

use nix::sys::mman::{mmap, ProtFlags, MapFlags};

use libc::off_t;

use std::cell::RefCell;
use std::fs::File;
use std::os::unix::io::AsRawFd;

use crate::Error;
use crate::memory::uintptr;

pub(crate) const KEYSTONE_IOC_MAGIC: usize = 0xa4;

pub(crate) const KEYSTONE_SUCCESS:     uintptr = 0;
pub(crate) const KEYSTONE_INTERRUPTED: uintptr = 100002;
pub(crate) const KEYSTONE_EDGE_CALL:   uintptr = 100011;

/// Path of the Keystone device file in Linux
pub const KEYSTONE_DEVICE_PATH: &str = "/dev/keystone_enclave";
/// Path describing a non-existing Keystone device
pub const KEYSTONE_NULL_DEVICE: &str = "null-device";

/// Enclave runtime parameters as defined by Keystone Security Monitor
// Defined by the Keystone Security Monitor: must not be changed!
#[derive(Default, Copy, Clone)]
#[repr(C, packed)]
pub struct RuntimeParams { // This is pub only because of ioctl_*
    /// Runtime entry point
    rt_entry:   uintptr,
    /// Enclave application entry point
    user_entry: uintptr,
    /// Untrusted shared memory base address
    shrd_base:  uintptr,
    /// Untrusted shared memory size in bytes
    shrd_size:  uintptr
}

impl RuntimeParams {

    pub(crate) fn new(rt_entry:   uintptr,
                      user_entry: uintptr,
                      shrd_base:  uintptr,
                      shrd_size:  usize)
                      -> Self {

        Self{rt_entry:   rt_entry,
             user_entry: user_entry,
             shrd_base:  shrd_base,
             shrd_size:  shrd_size}
    }
}

/// Parameters for Keystone driver operation to create an enclave
///
/// This structure is public only due to macro requirements!
// Defined by the Keystone Linux driver: must not be changed
#[derive(Default)]
#[repr(C)]
pub struct IoctlCreateEnclave { // This is pub only because of ioctl_*
    eid:        uintptr,
    min_pages:  uintptr,
    rt_vaddr:   uintptr,
    user_vaddr: uintptr, // Not used
    pt_ptr:     uintptr, // Not used
    shrd_free:  uintptr, // Not used
    priv_paddr: uintptr, // Not used
    shrd_paddr: uintptr, // Not used
    rt_paddr:   uintptr,
    user_paddr: uintptr,
    priv_free:  uintptr,
    priv_size:  uintptr, // Not used
    shrd_size:  uintptr, // Not used
    params:     RuntimeParams
}

/// Parameters for Keystone driver operation to run an enclave
///
/// This structure is public only due to macro requirements!
// Defined by the Keystone Linux driver: must not be changed
#[derive(Default)]
#[repr(C)]
pub struct IoctlRunEnclave { // This is pub only because of ioctl_*
    eid:   uintptr,
    error: uintptr,
    value: uintptr
}

ioctl_read!(     ioctl_create,   KEYSTONE_IOC_MAGIC, 0x00, IoctlCreateEnclave);
ioctl_write_ptr!(ioctl_destroy,  KEYSTONE_IOC_MAGIC, 0x01, IoctlCreateEnclave);
ioctl_read!(     ioctl_run,      KEYSTONE_IOC_MAGIC, 0x04, IoctlRunEnclave);
ioctl_read!(     ioctl_resume,   KEYSTONE_IOC_MAGIC, 0x05, IoctlRunEnclave);
ioctl_read!(     ioctl_finalize, KEYSTONE_IOC_MAGIC, 0x06, IoctlCreateEnclave);
ioctl_read!(     ioctl_utm_init, KEYSTONE_IOC_MAGIC, 0x07, IoctlCreateEnclave);

const INVALID_EID: uintptr = usize::MAX;

/// A handle for the Keystone pseudo-device operations
pub struct Device {
    /* Internal mutability: conceptually, once opened. the device stays the same
     * regardless of the enclave state in the driver. The 'eid' is used only for
     * record keeping internally and the device is used from the same thread.
     * Only changing the 'device_file' changes the device state in this sense.
     */
    eid:         RefCell<uintptr>,
    device_file: Option<File>,
}

impl Device {

    /// Open the Keystone pseudo-device
    pub(crate) fn new(path: &str) -> Result<Self, Error> {
        /* Open the device */
        if let Ok(file) = File::options().read(true).write(true).open(path) {
            return Ok(Self{eid:         RefCell::new(INVALID_EID),
                           device_file: Some(file)});
        }

        return Err(Error::Device);
    }

    /// Researve a new enclave
    ///
    /// Enclave will not be created until 'finalize_enclave' is called.
    pub(crate) fn create_enclave(&self, min_pages: usize) -> Result<uintptr, Error> {
        if self.device_file.is_none() {
            return Err(Error::BadState);
        }

        let mut data = IoctlCreateEnclave { min_pages: min_pages,
                                            .. Default::default() };

        let fd = self.device_file.as_ref().unwrap().as_raw_fd();
        if let Err(_code) = unsafe { ioctl_create(fd, &mut data) } {
            self.eid.replace(INVALID_EID);
            return Err(Error::Device);
        }

        self.eid.replace(data.eid);
        return Ok(data.pt_ptr);
    }

    /// Set encalve shared memory size
    pub(crate) fn init_shared_memory(&self, size: usize) -> Result<uintptr, Error> {

        if self.device_file.is_none() {
            return Err(Error::BadState);
        }

        let mut data = IoctlCreateEnclave { eid:    *self.eid.borrow(),
                                            params: RuntimeParams {
                                                shrd_size: size,
                                                .. Default::default()
                                            },
                                            .. Default::default() };

        let fd = self.device_file.as_ref().unwrap().as_raw_fd();
        if let Err(_code) = unsafe { ioctl_utm_init(fd, &mut data) } {
            return Err(Error::Device);
        }

        return Ok(data.shrd_free);
    }

    /// Finalize enclave initialization and instantiate the enclave
    pub(crate) fn finalize_enclave(&self,
                            rt_paddr:   uintptr,
                            user_paddr: uintptr,
                            free_paddr: uintptr,
                            params:     &RuntimeParams)
                            -> Result<(), Error> {

        if self.device_file.is_none() {
            return Err(Error::BadState);
        }

        let mut data = IoctlCreateEnclave { eid:        *self.eid.borrow(),
                                            rt_paddr:   rt_paddr,
                                            user_paddr: user_paddr,
                                            priv_free:  free_paddr,
                                            params:     *params,
                                            .. Default::default() };

        let fd     = self.device_file.as_ref().unwrap().as_raw_fd();
        if let Err(_code) = unsafe { ioctl_finalize(fd, &mut data) } {
            self.eid.replace(INVALID_EID);
            return Err(Error::Device);
        }

        Ok(())
    }

    /// destroy an enclave
    pub(crate) fn destroy_enclave(&self) -> Result<(), Error> {

        if *self.eid.borrow() == INVALID_EID {
            return Ok(());
        }

        if self.device_file.is_none() {
            return Err(Error::BadState);
        }

        let mut data = IoctlCreateEnclave { eid: *self.eid.borrow(),
                                            .. Default::default() };

        let fd     = self.device_file.as_ref().unwrap().as_raw_fd();
        let status = unsafe { ioctl_destroy(fd, &mut data) };
        if let Err(_code) = status {
            return Err(Error::Device);
        }

        self.eid.replace(INVALID_EID);
        return Ok(());
    }

    /// Start an enclave
    ///
    /// This call will block until the enclave stops execution
    pub(crate) fn run_enclave(&self) -> Result<uintptr, Error> {

        if self.device_file.is_none() {
            return Err(Error::BadState);
        }

        let mut data = IoctlRunEnclave { eid: *self.eid.borrow(), .. Default::default() };
        let fd       = self.device_file.as_ref().unwrap().as_raw_fd();
        if let Err(_code) = unsafe { ioctl_run(fd, &mut data) } {
            return Err(Error::Device);
        }

        return match data.error {
            KEYSTONE_EDGE_CALL   => Err(Error::Pending),
            KEYSTONE_INTERRUPTED => Err(Error::Interrupted),
            KEYSTONE_SUCCESS     => Ok(data.value),
            /* TODO: this masks all other SBI errors (SM): */
            _                    => Err(Error::Device),
        }
    }

    /// Resume an enclave that has stopped
    pub(crate) fn resume_enclave(&self) -> Result<uintptr, Error> {

        if self.device_file.is_none() {
            return Err(Error::BadState);
        }

        let mut data = IoctlRunEnclave { eid: *self.eid.borrow(), .. Default::default() };
        let fd       = self.device_file.as_ref().unwrap().as_raw_fd();
        if let Err(_code) = unsafe { ioctl_resume(fd, &mut data) } {
            return Err(Error::Device);
        }

        return match data.error {
            KEYSTONE_EDGE_CALL   => Err(Error::Pending),
            KEYSTONE_INTERRUPTED => Err(Error::Interrupted),
            KEYSTONE_SUCCESS     => Ok(data.value),
            /* TODO: this masks all other SBI errors (SM): */
            _                    => Err(Error::Device),
        }
    }

    /// Map address for the enclave
    pub(crate) fn map(&self, addr: uintptr, size: usize) -> Result<uintptr, Error>  {

        if self.device_file.is_none() {
            return Err(Error::BadState);
        }

        if let Ok(ptr)
            = unsafe {
                mmap(std::ptr::null_mut(),
                     size,
                     ProtFlags::PROT_READ| ProtFlags::PROT_WRITE,
                     MapFlags::MAP_SHARED,
                     self.device_file.as_ref().unwrap().as_raw_fd(),
                     addr as off_t) } {
                return Ok(ptr.to_bits());
        }

        return Err(Error::Device);
    }

}

impl Drop for Device {
    /* Destructor */
    fn drop(&mut self) {
        if let Err(_) = self.destroy_enclave() {
            // TODO
        }

        if self.device_file.is_some() {
            drop(self.device_file.as_mut());
        }
    }
}
