//! A builder pattern API for building Keystone enclaves
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

use sha3::Sha3_512;
use sha3::Digest;

use crate::Error;
use crate::binary::Binary;
use crate::device::{Device, RuntimeParams};
use crate::memory::{uintptr, Memory, Page, PageMode};
use crate::memory::{round_up, round_down, ceil};

/// Enclave builder
pub struct Builder {
    /// Position of the enclave runtime binary in the vector of binaries
    ert_pos:   usize,
    /// Binaries to be loaded
    binaries:  Vec<Binary>,
    /// Untrusted shared memory base address
    shrd_base: uintptr,
    /// Untrusted shared memory size in bytes
    shrd_size: usize,
    /// Free memory size in bytess
    free_size: usize,
}

/// Builder output
pub struct Output {
    /// Untrusted shared memory base address
    pub shrd_base: uintptr,
    /// Untrusted shared memory size in bytes
    pub shrd_size: uintptr,
    /// Hash of the built enclave private memory
    pub hash:      Vec<u8>,
}

impl Builder {

    pub(crate) const DEFAULT_STACK_SIZE:  usize = 1024 *16;
    pub(crate) const DEFAULT_STACK_START: usize = 0x0000000040000000;

    /// Default base address of the untrusted shared memory
    pub const DEFAULT_UNTRUSTED_PTR:      usize = 0xffffffff80000000;
    /// Default size of the untrusted shared memory in bytes
    pub const DEFAULT_UNTRUSTED_SIZE:     usize = 1024 * 1024;
    /// Default size of free memory
    pub const DEFAULT_FREE_MEMORY_SIZE:   usize = 1024 * 1024;

    /// Create a new enclave builder

    pub fn new() -> Self {
        Self { ert_pos:   usize::MAX,
               binaries:  Vec::new(),
               shrd_base: 0,
               shrd_size: 0,
               free_size: 0 }
    }

    /// Add a new binary to be loaded
    ///
    /// # Input
    /// * 'path' is the filesystem path to the binary file
    /// * 'runtime' should be set to 'true' if the binary represents the enclave
    ///             runtime
    ///
    /// # Return
    ///
    /// Ok() in case of success, otherwise an error value

    pub fn add(&mut self, path: &String, runtime: bool) -> Result<(), Error> {
        let binary = Binary::parse(path)?;
        if runtime {
            self.ert_pos = self.binaries.len();
        }
        self.binaries.push(binary);
        Ok(())
    }

    /// Setup parameters for untrusted shared memory
    ///
    /// # Input
    /// * 'base' is the base address
    /// * 'size' is the size of the memory area in bytes
    ///
    /// # Return
    ///
    /// Ok() in case of success, otherwise an error value

    pub fn setup_shared_memory(&mut self,
                               base: uintptr,
                               size: usize)
                               -> Result<(), Error> {

        if base == 0 || size == 0 {
            return Err(Error::BadArgument);
        }

        self.shrd_base = base;
        self.shrd_size = size;
        Ok(())
    }

    /// Setup parameters for free memory
    ///
    /// # Input
    /// * 'size' is the size of the memory area in bytes
    ///
    /// # Return
    ///
    /// Ok() in case of success, otherwise an error value

    pub fn setup_free_memory(&mut self, size: usize) -> Result<(), Error> {
        self.free_size = size;
        Ok(())
    }


    fn check(&self) -> bool {
        if self.binaries.len() == 0 {
            return false;
        }

        if self.ert_pos >= self.binaries.len() {
            return false;
        }

        if self.shrd_base == 0 || self.shrd_size == 0 {
            return false;
        }

        return true;
    }

    /// Build an enclave using the parameters loaded into the builder
    ///
    /// The operation accepts an optional Keystone pseudo-device parameters.
    /// If this parameter is supplied, the device is used to build the enclave.
    /// Otherwise, the builder simulates building the enclave private memory and
    /// calculates its hash. This can be used, e.g., to calculate a reference
    /// value for the enclave memory for attestation.
    ///
    /// # Input
    /// * 'device' is an potional Keystone pseudo-device
    ///
    /// # Return
    ///
    /// Ok(Output) containing parameters of the newly created enclave if
    /// the operation succeeded, othewise an error value

    pub fn build(&self, device: Option<&Device>) -> Result<Output, Error> {

        if !self.check() {
            return Err(Error::BadState);
        }

        // We only support two binaries currently:
        if self.binaries.len() != 2 {
            return Err(Error::NotImplemented);
        }

        let ert_bin   = &self.binaries[self.ert_pos];
        let app_bin   = &self.binaries[1 - self.ert_pos];
        let min_pages = round_up(self.free_size, Page::BITS) / Page::SIZE
            + ceil(app_bin.total_size(), Page::SIZE)
            + ceil(ert_bin.total_size(), Page::SIZE)
            + 15; // A magic number inherited from Keystone code

        // Create memory
        let mut memory =
            if let Some(ref dev) = device {
                let phys_addr = dev.create_enclave(min_pages)?;
                // NOTE: from mutable to immutable device
                //let some = Some(device);
                Memory::new(device, phys_addr, min_pages)?
            } else {
                Memory::new(None, 0, min_pages)?

            };

        // Load binaries, starting from runtime
        let ert_start = ert_bin.load(&mut memory, true)?;
        let app_start = app_bin.load(&mut memory, false)?;

        // Allocate stack
        let high_addr = round_up(Self::DEFAULT_STACK_START, Page::BITS);
        let low_addr  = round_down(high_addr - Self::DEFAULT_STACK_SIZE, Page::BITS);
        let num_pages = (high_addr - low_addr) / Page::SIZE;

        if memory.alloc_stack(low_addr, num_pages) != num_pages {
            return Err(Error::OutOfMemory); // TODO: not necessarily correct
        }

        // Allocate shared memory
        let shrd_base  = self.shrd_base;
        let shrd_size  = self.shrd_size;
        let shrd_end   = shrd_base + shrd_size;
        let shrd_start = memory.alloc_shared_memory(shrd_size)?;
        let va_start   = round_down(shrd_base, Page::BITS);
        let va_end     = round_up(shrd_end, Page::BITS);
        let num_pages  = (va_end - va_start) / Page::SIZE;

        for i in 0 .. num_pages {
            let page_addr = va_start + i * Page::SIZE;
            memory.alloc_page(page_addr, PageMode::SharedFull)?;
        }

        let free_start = memory.current_top();

        // Validate and hash
        let mut hash = Sha3_512::new();
        let params   = RuntimeParams::new(ert_bin.entry_point(),
                                          app_bin.entry_point(),
                                          shrd_base,
                                          shrd_size);

        // TODO: nicer way of hashing the struct content?
        let params_as_bytes: &[u8] = unsafe {
            core::slice::from_raw_parts((&params as *const RuntimeParams) as *const u8,
                                        core::mem::size_of::<RuntimeParams>())
        };

        hash.update(params_as_bytes);
        memory.validate(&mut hash,
                        ert_start,  app_start,
                        free_start, shrd_start)?;
        let hash = hash.finalize();

        // For a memory simulation we are done
        let shrd_base =
            if let Some(ref device) = device {
                device.finalize_enclave(ert_start, app_start,
                                        free_start, &params)?;
                device.map(0, shrd_size)?
            } else {
                shrd_base
            };

        Ok(Output{shrd_base: shrd_base,
                  shrd_size: self.shrd_size,
                  hash:      Vec::from(hash.as_slice())})
    }
}
