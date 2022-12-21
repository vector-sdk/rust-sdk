/* This file defines a symbol for the start address of the heap. The final
 * address and the size of the heap is defined by the linker script used when
 * linking the enclave application. The main motivation of this assembly file
 * is to force .malloc_zone section to be allocated, writable, and consist of
 * uninitialized data.
 *
 * SPDX-License-Identifier: MIT
 * Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd
 */

.section ".malloc_zone", "wa", @progbits
        .global __malloc_start
__malloc_start:
        .global __malloc_zone_stop
