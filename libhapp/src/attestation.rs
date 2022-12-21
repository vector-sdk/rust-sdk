//! An API for handling Keystone attestation reports.
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

use std::fmt;

pub use crate::internal::ed25519::PublicKey;
pub use crate::internal::ed25519::Signature;

pub use edge::attestation::{NONCE_MAX_LENGTH};
pub use edge::attestation::{REPORT_MAX_LENGTH};

/* Raw Keystone attestation report:
 *
 * -- Enclave report --
 *       64 bytes: integrity hash:
 *        8 bytes: data (nonce) length
 * 0 - 1024 bytes: data (nonce), real size is indicated by data length
 *       64 bytes: signature (hash, data length, data up to data length),
 *                 using SM pubkey
 * -- SM Report --
 *       64 bytes: integrity hash
 *       32 bytes: public key (SM)
 *       64 bytes: signature (hash, public key), using device public key
 * -- Device public key --
 *       32 bytes: public key
 */

const HASH_SIZE: usize = Hash::LENGTH;
const PKEY_SIZE: usize = PublicKey::LENGTH;
const SIGN_SIZE: usize = Signature::LENGTH;
const DLEN_SIZE: usize = std::mem::size_of::<u64>();

const ENC_OFFSET:             usize = 0;
const ENC_HASH_OFFSET:        usize = 0;
const ENC_DATA_LENGTH_OFFSET: usize = ENC_HASH_OFFSET + HASH_SIZE;
const ENC_DATA_OFFSET:        usize = ENC_DATA_LENGTH_OFFSET + DLEN_SIZE;
// const ENC_SIGN_OFFSET depends on DATA_LENGTH
const ENC_MIN_SIZE:           usize = ENC_DATA_OFFSET + SIGN_SIZE;

const SM_HASH_OFFSET: usize = 0;
const SM_PKEY_OFFSET: usize = SM_HASH_OFFSET + HASH_SIZE;
const SM_SIGN_OFFSET: usize = SM_PKEY_OFFSET + PKEY_SIZE;
const SM_TOTAL_SIZE:  usize = SM_SIGN_OFFSET + SIGN_SIZE;

const DEV_PKEY_OFFSET: usize = 0;
const DEV_TOTAL_SIZE:  usize = DEV_PKEY_OFFSET + PKEY_SIZE;

/// Attestation status codes
#[derive(Eq, PartialEq, Debug)]
pub enum AttestationResult {
    // Success
    Success = 0,
    /// The hash of the enclave didn't match given reference metric
    InvalidEnclaveHash,
    /// The user-specified nonce didn't match given reference metric
    InvalidUserData,
    /// The hash of the Secure Monitor didn't match given reference metric
    InvalidSecureMonitorHash,
    /// The key used to sign the Secure Monitor part of the report was incorrect
    InvalidDeviceKey,
    /// The key used to sign the enclave part of the report was incorrect
    InvalidSecureMonitorKey,
    /// The signature of the Secure Monitor part of the report was incorrect
    InvalidSecureMonitorSignature,
    /// The signature of the enclave part of the report was incorrect
    InvalidEnclaveSignature
}

impl fmt::Display for AttestationResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Attestation error codes
#[derive(Eq, PartialEq)]
pub enum AttestationError {
    /// Success
    Success = 0,
    /// One of the arguments was incorrect
    BadArgument,
    /// Data format of the payload data was incorrect
    BadFormat,
    /// The given public key has incorrect format
    BadPublicKey,
    /// One of the signaturesdoes not correspond to the expected public key
    BadSignature,
}

/// An object representing integrity hash
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Hash([u8; Hash::LENGTH]);

impl Hash {
    pub const LENGTH: usize = 64;

    /// Convert the Hash to a byte array.
    pub fn to_bytes(&self) -> [u8; Hash::LENGTH] {
        return self.0;
    }

    /// Get the Hash as a slice to the byte array.
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; Hash::LENGTH] {
        return &self.0
    }

    /// Create new Hash from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Hash, ()> {
        if bytes.len() != Hash::LENGTH {
            return Err(()/* TODO*/);
        }

        let mut raw: [u8; Hash::LENGTH] = [0u8; Hash::LENGTH];
        raw.copy_from_slice(&bytes[.. Hash::LENGTH]);

        return Ok(Hash(raw));
    }
}

/// Reference integrity metrics for a single enclave
pub struct ReferenceValues {
    /// Enclave hash
    enc_hash: Hash,
    /// Security Monitor hash
    sm_hash:  Hash,
    /// Device public key
    dev_pkey: PublicKey,
}

impl ReferenceValues {

    /// Create a new set of reference values
    ///
    /// # Input
    /// * 'enc_hash' is the hash of the enclave
    /// * 'sm_hash' is the hash of the Secure Monitor
    /// * 'dev_pkey' is the public key corresponding to device's private key
    ///
    /// # Return
    ///
    /// A new ReferenceValues object describing expected attestation report.

    pub fn new(enc: &Hash, sm: &Hash, pkey: &PublicKey) -> Self {
        return Self{enc_hash: *enc,
                    sm_hash:  *sm,
                    dev_pkey: *pkey};
    }

    /// Verify the enclave part of an attestation report
    fn verify_enclave(&self, evidence: &EnclaveReport, nonce: &[u8])
                      -> AttestationResult {

        let data = evidence.data();
        if data.len() != nonce.len() || data != nonce {
            return AttestationResult::InvalidUserData;
        }

        if evidence.hash().unwrap() != self.enc_hash {
            return AttestationResult::InvalidEnclaveHash;
        }

        return AttestationResult::Success;
    }

    /// Verify the Secure Monitor part of an attestation report
    fn verify_security_monitor(&self, evidence: &SecurityMonitorReport)
                      -> AttestationResult {

        if evidence.hash().unwrap() != self.sm_hash {
            return AttestationResult::InvalidSecureMonitorHash;
        }

        return AttestationResult::Success;
    }

    /// Verify the device part of an attestation report
    fn verify_device(&self, evidence: &DeviceIdentifier)
                     -> AttestationResult {

        match evidence.public_key() {
            Ok(key) => {
                if key != self.dev_pkey {
                    return AttestationResult::InvalidDeviceKey;
                }
            },
            Err(_) => {
                return AttestationResult::InvalidDeviceKey;
            },
        }

        return AttestationResult::Success;
    }

    /// Verify if an attestation evidence (report) matches given reference
    /// values
    ///
    /// # Input
    /// * 'evidence' is the attestation evidence to verify
    /// * 'nonce' is the user-specified used in attestation to guarantee
    ///           freshness of the evidence. It should match the nonce sent
    ///           to the enclave to generate the evidence.
    ///
    /// # Return
    ///
    /// A status code describing the result

    pub fn verify(&self, evidence: &Evidence, nonce: &[u8]) -> AttestationResult {

        // Verify that device identfier is as expected
        let result = self.verify_device(&evidence.device_identifier());
        if result != AttestationResult::Success {
            return result;
        }

        // Verify that the security monitor report is signed correctly with
        // device's attestation key:
        let srep = evidence.security_monitor();
        if !self.dev_pkey.verify(srep.report(), &srep.signature().unwrap()) {
            return AttestationResult::InvalidSecureMonitorSignature;
        }

        // Verify that the security monitor report is as expected
        let result = self.verify_security_monitor(&srep);
        if result != AttestationResult::Success {
            return result;
        }

        // Verify that the enclave report is signed by the security monitor
        let erep= evidence.enclave();
        if !srep.public_key().unwrap().verify(erep.report(),
                                            &erep.signature().unwrap()) {
            return AttestationResult::InvalidEnclaveSignature;
        }

        // Verify the enclave report
        let result = self.verify_enclave(&erep, nonce);
        if result != AttestationResult::Success {
            return result;
        }

        return AttestationResult::Success;
    }
}

/// Attestation evidence
pub struct Evidence {
    /// Raw attestation report
    raw: Vec<u8>,
    /// Byte offset into the beginning of the enclave report
    eoffs: usize,
    /// Byte offset into the beginning of security monitor report
    soffs: usize,
    /// Byte offset into the beginning of device identifier
    doffs: usize,
}

fn read_le_u64(slice: &[u8]) -> u64 {
    let (bytes, _) = slice.split_at(core::mem::size_of::<u64>());
    u64::from_le_bytes(bytes.try_into().unwrap())
}

impl Evidence {

    /// Get enclave part of the report
    pub fn enclave<'a>(&'a self) -> EnclaveReport {
        return EnclaveReport(&self.raw[self.eoffs .. self.soffs]);
    }

    /// Get Secure Monitor part of the report
    pub fn security_monitor(&self) -> SecurityMonitorReport {
        return SecurityMonitorReport(&self.raw[self.soffs .. self.doffs]);
    }

    /// Get device part of the report
    pub fn device_identifier(&self) -> DeviceIdentifier {
        return DeviceIdentifier(&self.raw[self.doffs .. ]);
    }

    /// Get the Evidence as a slice to the byte array.
    pub fn as_bytes(&self) -> &[u8] {
        return self.raw.as_slice();
    }

    /// Create new Evidence from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Evidence, AttestationError> {

        /* Check that the data is at least of the minimum size of the report: */
        let min_length = ENC_MIN_SIZE + SM_TOTAL_SIZE + DEV_TOTAL_SIZE;
        if bytes.len() < min_length {
            return Err(AttestationError::BadArgument);
        }

        /* Extract user data (nonce) length:*/
        let offset = ENC_OFFSET;
        let length = read_le_u64(&bytes[offset + ENC_DATA_LENGTH_OFFSET
                                        ..
                                        offset + ENC_DATA_OFFSET]) as usize;

        if length > NONCE_MAX_LENGTH {
            return Err(AttestationError::BadArgument);
        }

        /* Final check for data size: */
        if bytes.len() != min_length + length {
            return Err(AttestationError::BadArgument);
        }

        let e_offset = ENC_OFFSET;
        let s_offset = e_offset + ENC_MIN_SIZE + length;
        let d_offset = s_offset + SM_TOTAL_SIZE;

        return Ok(Evidence{raw:   bytes.to_vec(),
                           eoffs: e_offset,
                           soffs: s_offset,
                           doffs: d_offset});
    }
}

/// The enclave portion of Keystone attestation report
pub struct EnclaveReport<'a>(&'a[u8]);

impl <'a> EnclaveReport<'a> {

    /// Get length of the report in bytes
    pub fn data_length(&self) -> usize {
        return read_le_u64(&self.0[ENC_DATA_LENGTH_OFFSET
                                   ..
                                   ENC_DATA_OFFSET]) as usize;
    }

    /// Get byte slice containing the report data (nonce)
    pub fn data(&self) -> &[u8] {
        let offset = ENC_DATA_OFFSET;
        let length = self.data_length();
        return &self.0[offset .. offset + length];
    }

    /// Get hash of the enclave
    pub fn hash(&self) -> Result<Hash, ()> {
        let offset = ENC_HASH_OFFSET;
        let length = HASH_SIZE;
        return Hash::from_bytes(&self.0[offset .. offset + length]);
    }

    /// Get byte slice containing the full report
    pub fn report(&self) -> &[u8] {
        let offset = 0;
        let length = ENC_DATA_OFFSET + self.data_length();
        return &self.0[offset .. offset + length];
    }

    /// Get signature of the report
    ///
    /// The report is signed using Secure Monitor's attestation key
    pub fn signature(&self) -> Result<Signature, ()> {
        let offset = ENC_DATA_OFFSET + self.data_length();
        let length = SIGN_SIZE;
        return Signature::from_bytes(&self.0[offset .. offset + length]);
    }
}

/// The Security Monitor portion of a Keystone attestation report
pub struct SecurityMonitorReport<'a>(&'a[u8]);

impl <'a> SecurityMonitorReport<'a> {

    /// Get hash of the Secure Monitor
    pub fn hash(&self) -> Result<Hash, ()> {
        let offset = SM_HASH_OFFSET;
        let length = HASH_SIZE;
        return Hash::from_bytes(&self.0[offset .. offset + length]);
    }

    /// Get public portion of the attestation key of the Secure Monitor
    pub fn public_key(&self) -> Result<PublicKey, ()> {
        let offset = SM_PKEY_OFFSET;
        let length = PKEY_SIZE;
        return PublicKey::from_bytes(&self.0[offset .. offset + length]);
    }

    /// Get byte slice containing the full report
    pub fn report(&self) -> &[u8] {
        let offset = 0;
        let length = SM_SIGN_OFFSET;
        return &self.0[offset .. offset + length];
    }

    /// Get signature of the report
    ///
    /// The report is signed using device's attestation key
    fn signature(&self) -> Result<Signature, ()> {
        let offset = SM_SIGN_OFFSET;
        let length = SIGN_SIZE;
        return Signature::from_bytes(&self.0[offset .. offset + length]);
    }
}

/// The device portion of a Keystone attestation report
pub struct DeviceIdentifier<'a>(&'a[u8]);

impl <'a> DeviceIdentifier<'a> {

    /// Get public portion of the attestation key of the device
    pub fn public_key(&self) -> Result<PublicKey, ()> {
        let offset = DEV_PKEY_OFFSET;
        let length = PKEY_SIZE;
        return PublicKey::from_bytes(&self.0[offset .. offset + length]);
    }
}
