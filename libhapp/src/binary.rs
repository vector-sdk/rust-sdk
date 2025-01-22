//! An API for handling program binaries.
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022-2025 VTT Technical Research Centre of Finland Ltd

use std::fs::File;
use std::io::Read;

use elf_rs::Elf;
use elf_rs::ElfFile;
use elf_rs::ProgramType;

use crate::Error;
use crate::memory::{uintptr, Memory, Page, PageMode};
use crate::memory::{round_up, ceil, is_aligned};
use crate::builder::Loadable;

/// Executable program binary
///
/// Currently only presents 32 or 64 bit ELF binaries
pub(crate) struct Binary {
    /// Path to the executable file
    path:        String,
    /// The lowest virtual address used
    min_vaddr:   uintptr,
    /// the highest virtual address used
    max_vaddr:   uintptr,
    /// Executable entry point
    entry_point: uintptr,
    /// Size of the file in bytes
    file_size:   usize,
    /// Size of the text section in bytes
    text_size:   usize,
}

fn file_as_buffer(filename: &String) -> Result<Box<[u8]>, Error> {
    if let Ok(mut file) = File::options().read(true).open(filename) {
        let mut buffer = Vec::new();
        if file.read_to_end(&mut buffer).is_ok() {
            return Ok(buffer.into_boxed_slice());
        }
    }

    Err(Error::NotFound) // TODO: could be access error also
}

fn is_text_section(section_name: &[u8]) -> bool {
    const TEXT: &[u8] = b".text";
    section_name == TEXT
}

impl Binary {

    pub(crate) fn parse(path: &String) -> Result<Binary, Error> {
        let bytes = file_as_buffer(path)?;
        if let Ok(elf) = Elf::from_bytes(&bytes) {
            return Binary::new(path, &elf, bytes.len());
        }

        Err(Error::BadFormat)
    }

    fn check(elf: &Elf, size: usize) -> bool {
        // Assume that elf_rs crate checks the Elf header
        let header = elf.elf_header();

        // Check program header table:
        let offset = header.program_header_offset();
        let length = (header.program_header_entry_num()
                      *  header.program_header_entry_size()) as u64;
        let end    = offset + length;
        if (size as u64) < end || end < offset {
            return false;
        }

        // Check section header:
        let offset = header.section_header_offset();
        let length = (header.section_header_entry_num()
                      * header.section_header_entry_size()) as u64;
        let end    = offset + length;
        if (size as u64) < end || end < offset {
            return false;
        }

        return true;
    }

    fn new(path: &String, elf: &Elf, size: usize) -> Result<Binary, Error> {
        if !Binary::check(elf, size) {
            return Err(Error::BadFormat);
        }

        // Get memory bounds:
        let mut mem_min: u64 = u64::MAX;
        let mut mem_max: u64 = 0;

	// Get text section size
	let mut text_section_size: usize = 0;

        let is_virtual = true;
        for phdr in elf.program_header_iter() {
            if phdr.memsz() == 0 {
                continue;
            }

            let sect_min = if is_virtual {
                phdr.vaddr()
            } else {
                phdr.paddr()
            };

            let sect_max = sect_min + phdr.memsz();

            if sect_max > mem_max {
                mem_max = sect_max;
            }

            if sect_min < mem_min {
                mem_min = sect_min;
            }
        }

        if !is_aligned(mem_min as uintptr, Page::SIZE) {
            return Err(Error::BadFormat);
        }

	for section in elf.section_header_iter() {
	    if is_text_section(&section.section_name()) {
		text_section_size = section.content().len();
	    }
	}
	if text_section_size == 0 {
	    return Err(Error::BadFormat);
	}

        // The byte buffer and the ELF structure are not saved to avoid
        // problems with the borrow checker and lifetimes

        Ok(Self {path:        path.clone(),
                 min_vaddr:   mem_min as uintptr,
                 max_vaddr:   round_up(mem_max as uintptr, Page::BITS),
                 entry_point: elf.elf_header().entry_point() as uintptr,
                 file_size:   size,
	         text_size:   text_section_size})
    }

    pub(crate) fn total_size(&self) -> usize {
        return self.max_vaddr - self.min_vaddr;
    }

    pub(crate) fn text_size(&self) -> usize {
	return self.text_size;
    }

    pub(crate) fn entry_point(&self) -> uintptr {
        return self.entry_point;
    }

    pub(crate) fn load(&self,
                       memory: &mut Memory,
                       kind: Loadable)
                       -> Result<(uintptr, usize), Error> {

        let bytes = file_as_buffer(&self.path)?;
	let mut loaded: usize = 0;
        if self.file_size != bytes.len() {
            return Err(Error::BadArgument);
        }

        let elf   = match Elf::from_bytes(&bytes) {
            Ok(elf) => elf,
            Err(_)  => {
                return Err(Error::BadFormat);
            }
        };

        // TODO: we should really check that the file is the same
        //       e.g. calculate a hash of it or read it only once
        if !Binary::check(&elf, bytes.len()) {
            return Err(Error::BadFormat);
        }

        let start_addr = memory.current_top();
        let mode = match kind {
	    Loadable::Binary  => PageMode::UserFull,
	    Loadable::Runtime => PageMode::RuntimeFull,
	    Loadable::Loader  => PageMode::RuntimeFull,
	};

	if kind == Loadable::Loader {
            for phdr in elf.program_header_iter() {
		if phdr.ph_type() != ProgramType::LOAD {
                    continue;
		}
		let start       = phdr.vaddr() as uintptr;
		let src: &[u8]  = phdr.content();
		loaded = self.copy_file(src, start, mode, memory)?;
	    }
	} else {
            let start       = start_addr;
	    loaded = self.copy_file(&bytes, start, mode, memory)?;
        }
        Ok((start_addr, loaded))
    }

    fn copy_file(&self,
		 src: &[u8],
		 mut va: usize,
		 mode: PageMode,
		 memory: &mut Memory)
		 -> Result<usize, Error> {
	if !is_aligned(va, Page::SIZE) {
	    return Err(Error::InternalError)
	}
	let file_end = va + src.len();
	let memory_end = ceil(file_end, Page::SIZE) * Page::SIZE;
	let mut soffs = 0;

	// Copy bytes from the source and allocate memory pages
	while va + Page::SIZE <= file_end {
            if let Some(mut page) = memory.alloc_page(va, mode)? {
                page.write(0, &src[soffs .. soffs + Page::SIZE], false);
            }
            va    += Page::SIZE;
            soffs += Page::SIZE;
        }
        // Handle the last page and fill the rest of the page with zeros
	if va < file_end {
            if let Some(mut page) = memory.alloc_page(va, mode)? {
		page.write(0, &src[soffs .. soffs + file_end - va], true);
            }
            va += Page::SIZE;
	}
	// Check that the last memory address is matching
	if va != memory_end {
	    return Err(Error::InternalError);
	}
        Ok(va)
    }

}
