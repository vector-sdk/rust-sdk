//! Keystone Eyrie Runtime system calls
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

extern crate core;

use core::arch::asm;
use core::ffi::c_void;
use core::ptr::null_mut;
use core::ptr::null;

// Syscall numbers for Keystone Eyrie:
const SYSCALL_OCALL:           usize = 1001;
const SYSCALL_SHAREDCOPY:      usize = 1002;
const SYSCALL_ATTEST_ENCLAVE:  usize = 1003;
const SYSCALL_GET_SEALING_KEY: usize = 1004;
const SYSCALL_EXIT:            usize = 1101;

/// Perfom a system call to encalve runtime (Eyrie)
///
/// See: handle_syscall() in syscall.c of keystone-runtime

fn syscall(call: usize, arg0: usize, arg1: usize,
                  arg2: usize, arg3: usize, arg4: usize) -> usize {

    let rv;

    unsafe {
        asm!("ecall",
             in("a0") arg0, in("a1") arg1, in("a2") arg2,
             in("a3") arg3, in("a4") arg4, in("a7") call,
             lateout("a0") rv);
    }

    return rv;
}

fn syscall_noreturn(call: usize, arg0: usize, arg1: usize,
                           arg2: usize, arg3: usize, arg4: usize) -> ! {
    unsafe {
        asm!("ecall",
             in("a0") arg0, in("a1") arg1, in("a2") arg2,
             in("a3") arg3, in("a4") arg4, in("a7") call,
             options(noreturn));
    }
}

#[inline(always)]
fn sys_ocall(cid:  u64,
             ibuf: *const c_void,
             ilen: u64,
             obuf: *mut c_void,
             olen: u64)
             -> usize
{
    return syscall(SYSCALL_OCALL, cid  as usize,
                   ibuf as usize, ilen as usize,
                   obuf as usize, olen as usize);
}

/// Call to host application (ocall)
///
/// Call will be dispatched to a handler with the specified 'cid', if it is
/// registered in the host application. The buffer 'ibuf' will be copied into
/// the host application and any response will be copied to the enclave in the
/// buffer 'obuf'.
///
/// # Inputs
///
/// * 'cid'  is the call ID registered in the host application
/// * 'ibuf' is a byte buffer to send to the host application
/// * 'obuf' is a byte buffer where response from host application is written
///
/// # Returns
///
/// 0 if the call succeeded, 1 otherwise (as returned by Eyrie)

#[inline(always)]
#[allow(dead_code)]
pub(crate) fn ocall(cid: u64, ibuf: & [u8], obuf: & mut [u8]) -> usize {
    return sys_ocall(cid,
                     ibuf.as_ptr() as *const c_void,
                     ibuf.len() as u64,
                     obuf.as_mut_ptr() as *mut c_void,
                     obuf.len() as u64);
}

/// Call to host application (ocall)
///
/// Call will be dispatched to a handler with the specified 'cid', if it is
/// registered in the host application. The first 'ilen' bytes of the buffer
/// 'buf' will be copied into the host application. Any response will be written
/// to the same buffer 'buf'. At most 'olen' bytes of response are copied.
///
/// # Inputs
///
/// * 'cid'  is the call ID registered in the host application
/// * 'ibuf' is a byte buffer used exchange data with the host application
/// * 'ilen' is the number of bytes to send to the host application
/// * 'olen' is the maximum number of bytes to receive from the host application
///
/// # Returns
///
/// 0 if the call succeeded, 1 otherwise (as returned by Eyrie)

#[inline(always)]
#[allow(dead_code)]
pub(crate) fn ocall_inout(cid:  u64,
                          buf:  &mut [u8],
                          ilen: usize,
                          olen: usize)
                          -> usize {
    return sys_ocall(cid,
                     buf.as_ptr() as *const c_void,
                     ilen as u64,
                     buf.as_mut_ptr() as *mut c_void,
                     olen as u64);
}

/// Call to host application (ocall)
///
/// Call will be dispatched to a handler with the specified 'cid', if it is
/// registered in the host application. The buffer 'inbuf' will be copied into
/// the host application.
///
/// # Inputs
///
/// * 'cid'  is the call ID registered in the host application
/// * 'ibuf' is a byte buffer to send to the host application
///
/// # Returns
///
/// 0 if the call succeeded, 1 otherwise (as returned by Eyrie)

#[inline(always)]
#[allow(dead_code)]
pub(crate) fn ocall_out(cid: u64, ibuf: &[u8]) -> usize {
    return sys_ocall(cid,
                     ibuf.as_ptr() as *const c_void,
                     ibuf.len() as u64,
                     null_mut(),
                     0);
}

/// Call to host application (ocall)
///
/// Call will be dispatched to a handler with the specified 'cid', if it is
/// registered in the host application. Any response will be copied to the
/// enclave in the buffer 'obuf'.
///
/// # Inputs
///
/// * 'cid'  is the call ID registered in the host application
/// * 'obuf' is a byte buffer where response from host application is written
///
/// # Returns
///
/// 0 if the call succeeded, 1 otherwise (as returned by Eyrie)

#[inline(always)]
#[allow(dead_code)]
pub(crate) fn ocall_in(cid: u64, obuf: &mut [u8]) -> usize {
    return sys_ocall(cid,
                     null(),
                     0,
                     obuf.as_ptr() as *mut c_void,
                     obuf.len() as u64) ;
}

/// Call host application (ocall) with no input or output buffers.
///
/// # Inputs
///
/// * 'cid'  is the call ID registered in the host application
///
/// # Returns
///
/// 0 if the call succeeded, 1 otherwise (as returned by Eyrie)

#[inline(always)]
#[allow(dead_code)]
pub(crate) fn ocall_cid(cid: u64) -> usize {
    return sys_ocall(cid, null(), 0, null_mut(), 0);
}

/// Terminate the enclave application
///
/// # Inputs
///
/// * 'value' is the return value passed to the host application
///
/// # Returns
///
/// Never returns

#[inline(always)]
pub(crate) fn exit(value: u64) -> ! {
    syscall_noreturn(SYSCALL_EXIT, value as usize, 0, 0, 0, 0);
}

/// Retrieve attestation report from the security monitor
///
/// # Inputs
/// * 'to' is the buffer into which the report is written
/// * 'nonce' is user-specified nonce for freshness
///
/// # Returns
///
/// 0 if the call succeeded, 1 otherwise (as returned by Eyrie)

#[inline(always)]
pub(crate) fn attest_enclave(to: &mut [u8], nonce: &[u8]) -> usize
{
    return syscall(SYSCALL_ATTEST_ENCLAVE,
                   to.as_mut_ptr() as *mut c_void as usize,
                   nonce.as_ptr() as *const c_void as usize,
                   nonce.len() as u64 as usize,
                   0, 0);
}

/// Copy data from shared memory
///
/// # Inputs
/// * 'to' is the buffer into which the report is written
/// * 'from' is the byte offset in shared memory from which the copy starts
/// * 'n' is the number of bytes to be copied
///
/// # Returns
///
/// 0 if the call succeeded, 1 otherwise (as returned by Eyrie)


#[inline(always)]
#[allow(dead_code)]
pub(crate) fn copy_from_shared(to: &mut [u8], from: usize, n: usize) -> usize {

    // Check that all data copied actually fits into 'to'
    if to.len() < n {
        return 1; // TODO: ?
    }

    return syscall(SYSCALL_SHAREDCOPY,
                   to.as_mut_ptr() as *mut c_void as usize,
                   from, n, 0, 0);
}

/// Retrieve enclave instance specific sealing key from the security monitor
///
/// After the system call completes sucessfully, 'to' contains the sealing key
/// (the first 128 bytes) and a signature of the key (the next 64 bytes).
///
/// # Inputs
/// * 'to' is the buffer into which the report is written
///
/// # Returns
///
/// 0 if the call succeeded, 1 otherwise (as returned by Eyrie)


#[inline(always)]
#[allow(dead_code)]
pub(crate) fn sealing_key(to: &mut [u8], ident: &[u8]) -> usize {

    const SEALING_KEY_LENGTH: usize = 128;
    const SIGNATURE_LENGTH: usize   = 64;

    /* After the system call completes sucessfully, 'to' contains
     * the sealing key (the first 'SEALING_KEY_LENGTH' bytes) and
     * a signature of the key (the next 'SIGNATURE_LENGTH' bytes)
     */

    if to.len() < SEALING_KEY_LENGTH + SIGNATURE_LENGTH {
        return usize::MAX;
    }

    return syscall(SYSCALL_GET_SEALING_KEY,
                   to.as_mut_ptr() as *mut c_void as usize,
                   to.len() as u64 as usize,
                   ident.as_ptr() as *const c_void as usize,
                   ident.len() as u64 as usize,
                   0);
}
