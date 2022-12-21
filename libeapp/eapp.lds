/* An example linker script for Rust Keystone enclave application
 *
 * SPDX-License-Identifier: MIT
 * Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd
 */
OUTPUT_ARCH( "riscv" )

/* Use linker argument '--defsym HEAP_SIZE=<size>' to alter heap size. The size
 * must a multiple of page size (4096 bytes). Default value is 0. */
EXTERN(HEAP_SIZE)

ASSERT(DEFINED(HEAP_SIZE) ? HEAP_SIZE % 4096 == 0 : 1,
       "HEAP_SIZE must be multiple of page size (4096 bytes)")

/* Use linker argument '--defsym ECALL_INPUT_SIZE=<size>' to alter the amount of
 * space reserved for ecall input buffer. This option is only needed if feature
 * "heap_rt" is NOT used. Default value is 0.
 */
EXTERN(ECALL_INPUT_SIZE)

/* Use linker argument '--defsym ECALL_OUTPUT_SIZE=<size>' to alter the amount
 * of space reserved for ecall output buffer. This option is only needed if
 * feature "heap_rt" is NOT used. Default value is 0.
 */
EXTERN(ECALL_OUTPUT_SIZE)

/* ECall header is always 20 bytes */
ECALL_HEADER_LENGTH = 24;
/* Length of the ecall input buffer in bytes */
ECALL_IBUF_SIZE = DEFINED(ECALL_INPUT_SIZE)
                 ? ECALL_INPUT_SIZE + ECALL_HEADER_LENGTH
                 : 0;
/* Length of the ecall output buffer in bytes */
ECALL_OBUF_SIZE = DEFINED(ECALL_OUTPUT_SIZE)
                 ? ECALL_OUTPUT_SIZE + ECALL_HEADER_LENGTH
                 : 0;

/* Program's actual entry point before eapp_entry. Defined in libeapp */
ENTRY(_start)

PHDRS
{
/*   phdrs PT_PHDR PHDRS; */
   text  PT_LOAD FILEHDR PHDRS FLAGS(5);
   data  PT_LOAD FLAGS (6);
   alloc PT_LOAD FLAGS (6);
   bss   PT_LOAD;
}

SECTIONS
{
  /* The text section must be aligned to page boundary. Keystone
   * runtime will check it.
   */
  . = 0x00001000;
  .text : {
   /* The _start function should always be at address 0x00001000 */
    *(.text._start)
    *(.text)
    *(.text.*)
  } : text
  .rodata :
  {
    *(.rdata)
    *(.rodata)
    *(.rodata.*)
  } /* defaults to .text */
  . = ALIGN(0x1000);
  .data :  { *(.data) } : data
  .debug : { *(.debug) }

  /* Ecall buffers, in case feature "heap_rt" is not used */
  . = ALIGN(0x1000);
  .ecall_zone (NOLOAD):
  {
    *(.ecall_zone);
    PROVIDE(__ecall_inbuf_end    = DEFINED(__ecall_inbuf_start)
                                   ? . + ECALL_IBUF_SIZE
                                   : . );
    PROVIDE(__ecall_outbuf_start = DEFINED(__ecall_inbuf_start)
                                   ? . + ECALL_IBUF_SIZE
                                   : . );
    PROVIDE(__ecall_outbuf_end   = DEFINED(__ecall_inbuf_start)
                                   ? . + ECALL_IBUF_SIZE + ECALL_OBUF_SIZE
                                   : . );
    /* This statement enforces correct section size since the location counter
     * is not moved otherwise (only symbols are defined). However, if none of
     * the symbols are needed and .ecall_zone is effectively empty, this
     * statement also causes the linker not to remove the section (TODO?)
     */
    . = DEFINED(__ecall_inbuf_start)
        ? . + ECALL_IBUF_SIZE + ECALL_OBUF_SIZE
        : . ;
  } : alloc

  /* Section .malloc_zone and its symbols are used by the tiny malloc
   * included in the Keystone enclave application libraries.
   */
  . = ALIGN(0x1000);
  .malloc_zone (NOLOAD):
  {
    __malloc_zone_start = .;
    /* '__malloc_start' defined in libeapp will be placed here: */
    *(.malloc_zone);
    PROVIDE(__malloc_start = .);
    . = DEFINED(HEAP_SIZE) ? (. + HEAP_SIZE) : . ;
     PROVIDE(__malloc_zone_stop = .);
  } : alloc

  . = ALIGN(0x4);
  .bss :   { *(.bss)
             *(.bss.*) } : bss

  /* Unless specified, the linker by default outputs the .eh_frame section
   * before the text section, which moves the text section from the page
   * boundary, causing trouble with Eyrie, as the _start function will shift
   * from its intended address 0x00001000.
   */
  /DISCARD/ : {
    *(.eh_frame)
  }
  _end = .;
}
