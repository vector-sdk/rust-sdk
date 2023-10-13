//! Enclave memory builder
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd
use std::alloc::Layout;
use std::collections::HashMap;

use sha3::Sha3_512;
use sha3::Digest;

use crate::Error;
use crate::device::Device;

/* RISC-V definitions: */
const RISCV_PGLEVEL_MASK: usize = 0x1ff;
const RISCV_PGTABLE_HIGHEST_BIT: usize = 0x100;
const VA_BITS: usize = 39;
const RISCV_PGLEVEL_BITS: usize = 9;
const RISCV_PGSHIFT: usize = 12;
const RISCV_PGSIZE: usize = 1 << RISCV_PGSHIFT;
const PTE_PPN_SHIFT: usize = 10;
const RISCV_PGLEVEL_TOP: usize = (VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS;

/* Page table entry (PTE) fields */
const PTE_V: usize = 0x001; // Valid
const PTE_R: usize = 0x002; // Read
const PTE_W: usize = 0x004; // Write
const PTE_X: usize = 0x008; // Execute
const PTE_U: usize = 0x010; // User
#[allow(dead_code)]
const PTE_G: usize = 0x020; // Global
const PTE_A: usize = 0x040; // Accessed
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
    SharedFull
}

impl PageMode {
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
              free_offset: Page::SIZE} // Reserved
    }

    fn empty() -> Self {
        Self {size:        0,
              base:        std::ptr::null_mut(),
              base_offset: 0,
              free_offset: 0}
    }

    fn base_addr(&self) -> uintptr {
        self.base.expose_addr()
    }

    fn size(&self) -> usize {
        self.size
    }

    fn top(&self) -> uintptr {
        unsafe {
	    self.base.add(self.base_offset + self.free_offset).expose_addr()
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

struct PageTable<'a> {
    entries: &'a mut[uintptr],
}

impl <'a>PageTable<'a> {

    const BYTE_SIZE: usize = Page::SIZE;
    const SIZE: usize      = Self::BYTE_SIZE / PageTableEntry::SIZE;

    fn wrap(addr: uintptr) -> Self {
        let entries = unsafe {
            let ptr = std::ptr::from_exposed_addr_mut::<uintptr>(addr);
            std::slice::from_raw_parts_mut(ptr, Self::SIZE)
        };

        return Self{entries: entries};
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn value(&self, index: usize) -> uintptr {
        self.entries[index]
    }

    fn index(addr: uintptr, level: usize) -> usize {
        let idx: usize = addr >> (RISCV_PGLEVEL_BITS * level + RISCV_PGSHIFT);
        return idx & ((1 << RISCV_PGLEVEL_BITS) - 1);
    }
}

struct PageTableEntry {
    addr: uintptr,
}

impl PageTableEntry {

    const SIZE: usize = std::mem::size_of::<uintptr>();

    fn wrap(pte_addr: uintptr) -> Self {
        Self{addr: pte_addr}
    }

    fn value(&self) -> uintptr {
        unsafe {
            let addr = std::ptr::from_exposed_addr::<uintptr>(self.addr);
            return *addr;
        }
    }

    fn write(&mut self, value: uintptr, flags: usize) {
        let ppn = (value << PTE_PPN_SHIFT) | PTE_V | flags;
        unsafe {
            let addr = std::ptr::from_exposed_addr_mut::<uintptr>(self.addr);
            *addr = ppn;
        }
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
            let ptr = std::ptr::from_exposed_addr_mut::<u8>(vaddr);
            std::slice::from_raw_parts_mut(ptr, Page::SIZE)
        };

        return Self{content: content};
    }

    fn base_addr(&self) -> uintptr {
        self.content.as_ptr().expose_addr()
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

    pub(crate) fn fill(&mut self, byte: u8) {
        self.content.fill(byte);
    }

    pub(crate) fn content(&self) -> &[u8] {
        return self.content;
    }
}

pub(crate) struct Memory<'a> {
    device:   Option<&'a Device>,
    // Only present if device is present
    mappings: Option<HashMap<uintptr, uintptr>>,
    root_pgt: uintptr,
    priv_mem: MemoryArea,
    shrd_mem: MemoryArea,
}

impl <'a>Memory<'a> {

    pub(crate) fn new(device:    Option<&'a Device>,
               phys_addr: uintptr,
               min_pages: usize)
               -> Result<Self, Error> {

        let pm_size = min_pages * Page::SIZE;
        return if let Some(ref dev) = device {
            let root_page = dev.map(0, Page::SIZE)?;
            let base = std::ptr::from_exposed_addr_mut::<u8>(phys_addr);
            Ok(Self {device:   device,
                     mappings: Some(HashMap::new()),
                     root_pgt: root_page,
                     priv_mem: MemoryArea::new(base, pm_size),
                     shrd_mem: MemoryArea::empty() }) // Not allocated yet
        } else {
            let layout = Layout::from_size_align(pm_size, Page::SIZE).unwrap();
            let base   = unsafe { std::alloc::alloc_zeroed(layout) };
            if base == std::ptr::null_mut() {
                return Err(Error::OutOfMemory);
            }

            let priv_mem = MemoryArea::new(base, pm_size);
            // Allocate the root page table. Since this is the first allocation
            // it will always be at offset 0.
            let root_page = base.expose_addr();
            Ok(Self {device:   device,
                     mappings: None,
                     root_pgt: root_page,
                     priv_mem: priv_mem,
                     shrd_mem: MemoryArea::empty() }) // Not allocated yet
        };
    }

    /// Add page table entry for 'page_addr' to a page table in the memory area
    /// 'area'. Allocate new page table pages if necessary.

    fn create_pt_entry(&mut self, page_addr: uintptr) -> Result<PageTableEntry, Error> {

        let mut pt = PageTable::wrap(self.root_pgt);
        let until  = (VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS - 1;
        for i in (1 .. until + 1).rev() {
            let idx: usize = PageTable::index(page_addr, i);
            if 0 == (pt.entries[idx] & PTE_V) {
                // Page table is always allocated in the privat memory:
                let page = self.priv_mem.alloc_page()?;
                let free_ppn = page.base_addr() >> Page::BITS;
                pt.entries[idx] = (free_ppn << PTE_PPN_SHIFT) | PTE_V;
                return self.create_pt_entry(page_addr);
            }

            let addr = (pt.entries[idx] >> PTE_PPN_SHIFT) << RISCV_PGSHIFT;
            let addr = self.map_priv_page(addr)?;
            pt = PageTable::wrap(addr);
        }

        let offset = PageTable::index(page_addr, 0) * PageTableEntry::SIZE;
        let addr   = pt.entries.as_ptr().expose_addr() + offset;
        assert!(addr != 0);
        return Ok(PageTableEntry::wrap(addr));
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

    fn paddr_to_vaddr(&self, paddr: uintptr) -> Result<uintptr, Error> {
        if self.mappings.is_none() {
            return Ok(paddr);
        }

        match self.mappings.as_ref().unwrap().get(&paddr) {
            Some(vaddr) => Ok(*vaddr),
            None        => Err(Error::Unknown) /* TODO */
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
            self.shrd_mem.base = std::ptr::from_exposed_addr_mut::<u8>(addr);
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


    pub(crate) fn alloc_vspace(&mut self,
                               min_vaddr: uintptr,
                               num_pages: usize)
                               -> usize {
        for count in 0 .. num_pages {
            let page_addr = min_vaddr + count * Page::SIZE;
            if self.create_pt_entry(page_addr).is_err() {
                return count;
            }

        }

        return num_pages;
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
                             vaddr: uintptr,
                             mode: PageMode)
                             -> Result<Option<Page>, Error> {

        let mut pt_entry = self.create_pt_entry(vaddr)?;

        /* Already allocated */
        if (pt_entry.value() & PTE_V) != 0 {
            return Ok(None);
        }

        let memory =
            if mode == PageMode::SharedFull {
                &mut self.shrd_mem
            } else {
                &mut self.priv_mem
            };

        let page  = memory.alloc_page()?;
        let page_addr = page.base_addr();
        pt_entry.write(page_addr >> Page::BITS, mode.as_usize());
        let page_addr =
            if mode == PageMode::UserFull || mode == PageMode::RuntimeFull {
                self.map_priv_page(page_addr)?
            } else {
                page_addr
            };

        return Ok(Some(Page::wrap(page_addr)));
    }


    pub(crate) fn validate(&self,
                           hash:       &mut Sha3_512,
                           rt_start:   uintptr,
                           user_start: uintptr,
                           free_start: uintptr,
                           shrd_start: uintptr)
                           -> Result<(), Error> {

        let mut rt_max_seen:   uintptr = 0;
        let mut user_max_seen: uintptr = 0;
        self.validate_internal (hash,
                                rt_start,
                                user_start,
                                free_start,
                                shrd_start,
                                RISCV_PGLEVEL_TOP as i32,
                                self.root_pgt,
                                0,
                                false,
                                &mut rt_max_seen,
                                &mut user_max_seen)?;
        Ok(())
    }

    pub(crate) fn validate_internal(&self,
                                    hash:           &mut Sha3_512,
                                    rt_start:   uintptr,
                                    user_start: uintptr,
                                    free_start: uintptr,
                                    shrd_start: uintptr,
                                    level:          i32,
                                    pt_addr:        uintptr,
                                    vaddr:          uintptr,
                                    contig:         bool,
                                    rt_max_seen:    &mut uintptr,
                                    user_max_seen:  &mut uintptr)
                                    -> Result<bool, Error> {

        let mut contiguous = contig;
        let pt_page = PageTable::wrap(pt_addr);

        for i in 0 .. pt_page.len() {
            let pte_value = pt_page.value(i);

            if pte_value == 0 {
                contiguous = false;
                continue;
            }

            let phys_addr = (pte_value >> PTE_PPN_SHIFT) << RISCV_PGSHIFT;

            let priv_mem   = &self.priv_mem;
            let priv_start = priv_mem.base_addr();
            let priv_end   = priv_start + priv_mem.size();
            let in_priv    = phys_addr >= priv_start && phys_addr < priv_end;

            let shrd_mem = &self.shrd_mem;
            let shrd_end = shrd_start + shrd_mem.size();
            let in_shrd  = phys_addr >= shrd_start && phys_addr < shrd_end;

            // EPM may map anything, UTM may not map pgtables
            if !in_priv && (!in_shrd || level != 1) {
                return Err(Error::BadFormat);
            }

            // propagate the highest bit of the VA
            let vpn =
                if (level as usize == RISCV_PGLEVEL_TOP)
                    && ((i & RISCV_PGTABLE_HIGHEST_BIT) != 0) {
                    (usize::MAX << RISCV_PGLEVEL_BITS) | (i & RISCV_PGLEVEL_MASK)
                } else {
                    (vaddr << RISCV_PGLEVEL_BITS) | (i & RISCV_PGLEVEL_MASK)
                };

            let va_start: uintptr = vpn << RISCV_PGSHIFT;

            if level == 1 {
                // include the first virtual address of a contiguous range
                if !contiguous {
                    hash.update(va_start.to_le_bytes());
                    contiguous = true;
                }

                let in_rt   = (phys_addr >= rt_start) && (phys_addr < user_start);
                let in_user = (phys_addr >= user_start)  && (phys_addr < free_start);

                /* Validate U bit */
                if in_user && ((pte_value & PTE_U) == 0) {
                    return Err(Error::BadFormat);
                }

                if va_start >= shrd_start && va_start < shrd_end && !in_shrd {
                    return Err(Error::BadFormat);
                }

                /* Do linear mapping validation */
                if in_rt {
                    if phys_addr <= *rt_max_seen {
                        return Err(Error::BadFormat);
                    }

                    *rt_max_seen = phys_addr;
                } else if in_user {
                    if phys_addr <= *user_max_seen {
                        return Err(Error::BadFormat);
                    }

                    *user_max_seen = phys_addr;
                } else if in_shrd {
                    // we checked this above, its OK
                } else {
                    return Err(Error::BadFormat);
                }

                // Page is valid, add it to the hash

                if let Ok(phys_addr) = self.paddr_to_vaddr(phys_addr) {
                    let page = Page::wrap(phys_addr);
                    hash.update(page.content());
                } else { // Not mapped, will be a zeroed page
                    let content: [u8; Page::SIZE] = [0; Page::SIZE];
                    hash.update(content);
                }

            } else {
                let phys_addr = self.paddr_to_vaddr(phys_addr)?;

                /* otherwise, recurse on a lower level */
                contiguous = self.validate_internal(hash,
                                                    rt_start,
                                                    user_start,
                                                    free_start,
                                                    shrd_start,
                                                    level - 1,
                                                    phys_addr,
                                                    vpn,
                                                    contiguous,
                                                    rt_max_seen,
                                                    user_max_seen)?;
            }
        }

        return Ok(contiguous);
    }
}
