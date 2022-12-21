//! An API for Keystone attestation within the enclave
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

extern crate core;

use crate::Status;
use crate::internal::syscall;

pub use edge::attestation::{NONCE_MAX_LENGTH};
pub use edge::attestation::{REPORT_MAX_LENGTH};

/* Raw Keystone attestation report:
 *
 * -- Enclave report --
 *   64 bytes: integrity hash:
 *    8 bytes: data (nonce) length
 * 1024 bytes: data (nonce), bytes after data length contain garbage
 *   64 bytes: signature (hash, data length, data up to data length),
 *             using SM pubkey
 * -- SM Report --
 *  64 bytes: integrity hash
 *  32 bytes: public key (SM)
 *  64 bytes: signature (hash, public key), using device public key
 * -- Device public key --
 *  32 bytes: public key
 * -- Garbage --
 *  All remaining bytes up to the maximum report size of 2048 bytes.
 */

const HASH_SIZE: usize = 64;
const PKEY_SIZE: usize = 32; // ed25519
const SIGN_SIZE: usize = 64; // ed25519
const DLEN_SIZE: usize = core::mem::size_of::<u64>();

const ENC_HASH_OFFSET:        usize = 0;
const ENC_DATA_LENGTH_OFFSET: usize = ENC_HASH_OFFSET + HASH_SIZE;
const ENC_DATA_OFFSET:        usize = ENC_DATA_LENGTH_OFFSET + DLEN_SIZE;

#[allow(dead_code)]
const SM_HASH_OFFSET: usize = 0;
#[allow(dead_code)]
const SM_PKEY_OFFSET: usize = SM_HASH_OFFSET + HASH_SIZE;
#[allow(dead_code)]
const SM_SIGN_OFFSET: usize = SM_PKEY_OFFSET + PKEY_SIZE;

const RAW_DATA_MAX_LEN:      usize = NONCE_MAX_LENGTH;
const RAW_ENC_REPORT_OFFSET: usize = 0;
const RAW_ENC_REPORT_SIZE:   usize = HASH_SIZE + DLEN_SIZE + RAW_DATA_MAX_LEN + SIGN_SIZE;
const RAW_SM_REPORT_OFFSET:  usize = RAW_ENC_REPORT_OFFSET + RAW_ENC_REPORT_SIZE;
#[allow(dead_code)]
const RAW_SM_REPORT_SIZE:    usize = HASH_SIZE + PKEY_SIZE + SIGN_SIZE;
#[allow(dead_code)]
const RAW_DEV_PKEY_OFFSET:   usize = RAW_SM_REPORT_OFFSET + RAW_SM_REPORT_SIZE;
const RAW_DEV_PKEY_SIZE:     usize = PKEY_SIZE;
const RAW_REPORT_SIZE:       usize = RAW_ENC_REPORT_SIZE + RAW_SM_REPORT_SIZE + RAW_DEV_PKEY_SIZE;

fn read_le_u64(slice: &[u8]) -> u64 {
    let (bytes, _) = slice.split_at(core::mem::size_of::<u64>());
    u64::from_le_bytes(bytes.try_into().unwrap())
}

/// Compress the attestation report by discarding extra bytes in the nonce and
/// end of the report which result from Keystone Security Monitor and the Eyrie
/// runtime's requirement of certain buffer size.
///
/// # Inputs
///
/// * 'report' is a buffer into which the report is to be written. It must be
///    at least 'REPORT_MAX_LENGTH' bytes long.
///
/// # Returns
///
/// Returns a 'Result' where the 'Ok' value contains the number of bytes written
/// into the 'report' buffer in case the operation was successfull and the 'Err'
/// value constains a 'Status' code indicating the reason of failure.
///

fn compress(report: &mut [u8]) -> Result<usize, Status> {

    /* Assure that the buffer is at least the minimum report size, i.e., size of
     * a valid report with RAW_DATA_MAX_LEN nonce. If so, the buffer should be
     * big enough for the final data since we are compressing the report.
     * Everything after the maximum size is discarded.
     */

    if report.len() < RAW_REPORT_SIZE {
        return Err(Status::ShortBuffer);
    }

    let offset = RAW_ENC_REPORT_OFFSET;
    let data_length = read_le_u64(&report[offset + ENC_DATA_LENGTH_OFFSET
                                          ..
                                          offset + ENC_DATA_OFFSET]) as usize;

    if data_length> RAW_DATA_MAX_LEN {
        return Err(Status::BadPointer);
    }

    let length       = SIGN_SIZE + RAW_SM_REPORT_SIZE + PKEY_SIZE;
    let to_offset    = offset + ENC_DATA_OFFSET + data_length;
    let from_offset  = offset + ENC_DATA_OFFSET + RAW_DATA_MAX_LEN;
    let total        = to_offset + length;


    report.copy_within(from_offset .. from_offset + length, to_offset);

    return Ok(total);
}


/// Retrive a raw attestation report from the Keystone Security Monitor. The
/// report may include a caller-specified 'nonce'.
///
/// The report is compressed from Security Monitor's raw buffer format by
/// discarding all the bytes that do not contain meaningfull data, i.e., the
/// space reserved for a nonce of the maximum length and the excess space at the
/// end of the buffer (Security Monitor always returns 2048 bytes).
///
/// # Inputs
///
/// * 'nonce' is a caller specified message that is to be included into the
///   report. The maximum lentgh of the nonce is 'NONCE_MAX_LENGTH' bytes.
///
/// * 'report' is a buffer into which the report is to be written. It must be
///    at least 'REPORT_MAX_LENGTH' bytes long.
///
/// # Returns
///
/// Returns a 'Result' where the 'Ok' value contains the number of bytes written
/// into the 'report' buffer in case the operation was successfull and the 'Err'
/// value constains a 'Status' code indicating the reason of failure.
///


pub fn attest(nonce: &[u8], report: &mut [u8]) -> Result<usize, Status> {

    if report.len() < REPORT_MAX_LENGTH {
        return Err(Status::ShortBuffer);
    }

    if nonce.len() > NONCE_MAX_LENGTH {
        return Err(Status::BadPointer);
    }

    if 0 != syscall::attest_enclave(report, nonce) {
        return Err(Status::Error);
    }

    return compress(report);
}
