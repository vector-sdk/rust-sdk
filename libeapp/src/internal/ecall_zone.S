/* This code provides a way to define ecall input and output buffers
 * at link-time. This is only needed if feature "heap_rt" is not used.
 *
 * SPDX-License-Identifier: MIT
 * Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd
 */

.section ".ecall_zone", "wa", @progbits
        .global __ecall_inbuf_start
__ecall_inbuf_start:
        .global __ecall_inbuf_end
        .global __ecall_outbuf_start
        .global __ecall_outbuf_end
