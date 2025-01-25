//! Enclave memory builder
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022-2025 VTT Technical Research Centre of Finland Ltd
use std::alloc::Layout;
use std::collections::HashMap;

use crate::Error;
use crate::device::Device;

/* RISC-V definitions: */
#[allow(dead_code)]
const RISCV_PGLEVEL_MASK: usize = 0x1ff;
#[allow(dead_code)]
const RISCV_PGTABLE_HIGHEST_BIT: usize = 0x100;
const VA_BITS: usize = 39;
const RISCV_PGLEVEL_BITS: usize = 9;
const RISCV_PGSHIFT: usize = 12;
const RISCV_PGSIZE: usize = 1 << RISCV_PGSHIFT;
#[allow(dead_code)]
const PTE_PPN_SHIFT: usize = 10;
#[allow(dead_code)]
const RISCV_PGLEVEL_TOP: usize = (VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS;

/* Page table entry (PTE) fields */
#[allow(dead_code)]
const PTE_V: usize = 0x001; // Valid
#[allow(dead_code)]
const PTE_R: usize = 0x002; // Read
#[allow(dead_code)]
const PTE_W: usize = 0x004; // Write
#[allow(dead_code)]
const PTE_X: usize = 0x008; // Execute
#[allow(dead_code)]
const PTE_U: usize = 0x010; // User
#[allow(dead_code)]
const PTE_G: usize = 0x020; // Global
#[allow(dead_code)]
const PTE_A: usize = 0x040; // Accessed
#[allow(dead_code)]
const PTE_D: usize = 0x080; // Dirty
#[allow(dead_code)]
const PTE_SOFT: usize =  0x300; // Reserved for Software

#[allow(non_camel_case_types)]
pub(crate) type uintptr = usize;

#[allow(dead_code)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum PageMode {
    RuntimeNoExec ,
    UserNoExec,
    RuntimeFull,
    UserFull,
    SharedFull,
}

impl PageMode {
    #[allow(dead_code)]
    fn as_usize(&self) -> usize {
        return match *self {
            PageMode::UserNoExec =>
                PTE_D | PTE_A | PTE_R | PTE_W | PTE_U | PTE_V,
            PageMode::RuntimeNoExec =>
               PTE_D | PTE_A | PTE_R | PTE_W | PTE_V,
            PageMode::RuntimeFull =>
                PTE_D | PTE_A | PTE_R | PTE_W | PTE_X | PTE_V,
            PageMode::UserFull =>
                PTE_D | PTE_A | PTE_R | PTE_W | PTE_X | PTE_U | PTE_V,
            PageMode::SharedFull =>
                PTE_D | PTE_A | PTE_R | PTE_W | PTE_V,
        };
    }
}

pub(crate) fn is_aligned(addr: uintptr, align: usize) -> bool {
    (addr & (align - 1)) == 0
}

pub(crate) fn round_up(n: usize, b: usize) -> usize {
    (((n - 1 as usize) >> b) + 1 as usize) << b
}

pub(crate) fn round_down(n: usize, b: usize) -> usize {
    n & !((2 << (b - 1)) - 1)
}

pub(crate) fn ceil(n: usize, d: usize) -> usize {
    n / d + (n % d != 0) as usize
}

struct MemoryArea {
    size:        usize,   // Total memory area size
    base:        *mut u8, // Actual memory base pointer
    base_offset: usize,   // Offset to memory base (currently always zero)
    free_offset: usize,   // Offset to the next free page
}

impl MemoryArea {

    fn new(base: *mut u8,size: usize) -> Self {
        Self {size:        size,
              base:        base,
              base_offset: 0,
              free_offset: 0}
    }

    fn empty() -> Self {
        Self {size:        0,
              base:        std::ptr::null_mut(),
              base_offset: 0,
              free_offset: 0}
    }

    fn base_addr(&self) -> uintptr {
        self.base.expose_provenance()
    }

    #[allow(dead_code)]
    fn size(&self) -> usize {
        self.size
    }

    fn top(&self) -> uintptr {
        unsafe {
	    self.base.add(self.base_offset + self.free_offset).expose_provenance()
	}
    }

    fn alloc_page(&mut self) -> Result<Page, Error> {
        if self.free_offset + Page::SIZE > self.size {
            // TODO: Memory allocation failed (device or allocator)
            // or run out of allocated memory:
            return Err(Error::OutOfMemory);
        }

        let vaddr = self.top();
        self.free_offset += Page::SIZE;
        Ok(Page::wrap(vaddr))
    }
}

pub(crate) struct Page<'a> {
    content: &'a mut [u8],
}

impl <'a>Page<'a>  {

    pub(crate) const SIZE: usize = RISCV_PGSIZE;
    pub(crate) const BITS: usize = RISCV_PGSHIFT;

    fn wrap(vaddr: uintptr) -> Self {
        let content = unsafe {
            let ptr = std::ptr::with_exposed_provenance_mut::<u8>(vaddr);
            std::slice::from_raw_parts_mut(ptr, Page::SIZE)
        };

        return Self{content: content};
    }

    fn base_addr(&self) -> uintptr {
        self.content.as_ptr().expose_provenance()
    }

    pub(crate) fn write(&mut self,
                        offset: usize,
                        data:   &[u8],
                        zero:   bool)
                        -> bool {

        let end = offset + data.len();
        if end > Page::SIZE {
            return false;
        }

        if zero && offset > 0 {
            self.content[0 .. offset].fill(0);
        }

        self.content[offset .. end].clone_from_slice(data);

        if zero && end < Page::SIZE {
            self.content[end .. Page::SIZE].fill(0);
        }

        return true;
    }

    #[allow(dead_code)]
    pub(crate) fn fill(&mut self, byte: u8) {
        self.content.fill(byte);
    }

    #[allow(dead_code)]
    pub(crate) fn content(&self) -> &[u8] {
        return self.content;
    }
}

pub(crate) struct Memory<'a> {
    device:   Option<&'a Device>,
    // Only present if device is present
    mappings: Option<HashMap<uintptr, uintptr>>,
    priv_mem: MemoryArea,
    shrd_mem: MemoryArea,
}

impl <'a>Memory<'a> {

    pub(crate) fn new(device:    Option<&'a Device>,
               phys_addr: uintptr,
               min_pages: usize)
               -> Result<Self, Error> {

        let pm_size = min_pages * Page::SIZE;
        return if let Some(ref _dev) = device {
            let base = std::ptr::with_exposed_provenance_mut::<u8>(phys_addr);
            Ok(Self {device:   device,
                     mappings: Some(HashMap::new()),
                     priv_mem: MemoryArea::new(base, pm_size),
                     shrd_mem: MemoryArea::empty() }) // Not allocated yet
        } else {
            let layout = Layout::from_size_align(pm_size, Page::SIZE).unwrap();
            let base   = unsafe { std::alloc::alloc_zeroed(layout) };
            if base == std::ptr::null_mut() {
                return Err(Error::OutOfMemory);
            }

            let priv_mem = MemoryArea::new(base, pm_size);
            Ok(Self {device:   device,
                     mappings: None,
                     priv_mem: priv_mem,
                     shrd_mem: MemoryArea::empty() }) // Not allocated yet
        };
    }

    fn map_priv_page(&mut self, page_addr: uintptr) -> Result<uintptr, Error> {
        if let Some(ref device) = self.device {
            let offset = page_addr - self.priv_mem.base_addr();
            let addr   = device.map(offset, Page::SIZE)?;
            assert!(self.mappings.is_some());
            self.mappings.as_mut().unwrap().insert(page_addr, addr);
            Ok(addr)
        } else {
            Ok(page_addr)
        }
    }

    pub(crate) fn alloc_shared_memory(&mut self,
                                      size: usize)
                                      -> Result<uintptr, Error> {

        if self.shrd_mem.base != std::ptr::null_mut() {
            return Err(Error::BadState);
        }

        if let Some(ref device) = self.device {
            let addr = device.init_shared_memory(size)?;
            self.shrd_mem.size = size;
            self.shrd_mem.base = std::ptr::with_exposed_provenance_mut::<u8>(addr);
            self.shrd_mem.base_offset = 0;
            self.shrd_mem.free_offset = 0;
            return Ok(addr);
        } else {
            let layout = Layout::from_size_align(size, Page::SIZE).unwrap();
            self.shrd_mem.size = size;
            self.shrd_mem.base = unsafe { std::alloc::alloc_zeroed(layout) };
            self.shrd_mem.base_offset = 0;
            self.shrd_mem.free_offset = 0;
            return Ok(self.shrd_mem.base_addr());
        }
    }

    pub(crate) fn current_top(&self) -> uintptr  {
        return self.priv_mem.top();
    }

    pub(crate) fn alloc_stack(&mut self,
                              min_vaddr: uintptr,
                              num_pages: usize)
                              -> usize {

        for count in 0 .. num_pages {
            let page_addr = min_vaddr + count * Page::SIZE;
            if self.alloc_page(page_addr, PageMode::UserNoExec).is_err() {
                return count;
            }
        }

        return num_pages;
    }

    pub(crate) fn alloc_page(&mut self,
                             _vaddr: uintptr,
                             mode: PageMode)
                             -> Result<Option<Page>, Error> {

        let memory =
            if mode == PageMode::SharedFull {
                &mut self.shrd_mem
            } else {
                &mut self.priv_mem
            };

        let page  = memory.alloc_page()?;
        let page_addr = page.base_addr();
        let page_addr =
            if mode == PageMode::UserFull || mode == PageMode::RuntimeFull {
                self.map_priv_page(page_addr)?
            } else {
                page_addr
            };

        return Ok(Some(Page::wrap(page_addr)));
    }

}
