//! A minimalistic implementation of ed25519 with SHA-3 hash.
//!
//! This API aims to mimic that of the other crypto APIs so that it could be
//! changed to some other library. The main reason for having this
//! implementation is that no Rust library for ed25519 with SHA-3 (not SHA-2)
//! could be found.
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;

use sha3::Sha3_512;
use sha3::Digest;

/// A public key
///
/// Currently only supports ed25519 elliptic curve keys.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PublicKey {
    /// Raw public key
    raw: [u8; PublicKey::LENGTH],
}

impl PublicKey {

    /// Size of a public key in bytes.
    pub const LENGTH: usize = 32;

    /// Convert the public key to a byte array.
    pub fn to_bytes(&self) -> [u8; PublicKey::LENGTH] {
        return self.raw;
    }

    /// Get the public key as slice to the byte array.
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; PublicKey::LENGTH] {
        return &self.raw
    }

    /// Create new PulibKey from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, ()> {
        if bytes.len() != PublicKey::LENGTH {
            return Err(()/* TODO*/);
        }

        let mut raw: [u8; PublicKey::LENGTH] = [0u8; PublicKey::LENGTH];
        raw.copy_from_slice(&bytes[.. PublicKey::LENGTH]);

        Ok(PublicKey{raw: raw})
    }

    /// Verify a 'signature' of a 'msg' using a PublicKey
    ///
    /// # Inputs:
    ///
    /// * 'msg' is the signed data
    ///
    /// * 'signature' is the signature to verify.
    ///
    /// # Returns
    ///
    /// Returns 'true' or 'false' depending if the verification succeeds or not

    #[allow(non_snake_case)]
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> bool
    {
        let mut h = Sha3_512::new();
        let sig_r = compressed_point_from_bytes(&signature.as_bytes()[.. 32]).unwrap();
        let sig_s = scalar_from_bytes(&signature.as_bytes()[32 ..]).unwrap();
        let sig_A = point_from_bytes(&self.as_bytes()[.. 32]).unwrap();
        let sig_R = match sig_r.decompress() {
            Some(x) => x,
            None => return false
        };

        if sig_R.is_small_order() || sig_A.is_small_order() {
            return false;
        }

        h.update(sig_r.as_bytes());
        h.update(self.as_bytes());
        h.update(&msg);

        let k = Scalar::from_hash(h);
        let R = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &(-sig_A), &sig_s);

        return R == sig_R;
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
/// An ed25519 signature
pub struct Signature {
    /// Raw signature
    raw: [u8; Signature::LENGTH],
}

impl Signature {

    /// Size of a signature in bytes.
    pub const LENGTH: usize = 64;

    /// Convert the Signature to a byte array.
    pub fn to_bytes(&self) -> [u8; Signature::LENGTH] {
        return self.raw;
    }

    /// Get the Signature as a slice to the byte array.
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; Signature::LENGTH] {
        return &self.raw
    }

    /// Create new Signature from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Signature, ()> {
        if bytes.len() != Signature::LENGTH {
            return Err(()/* TODO*/);
        }

        let mut raw: [u8; Signature::LENGTH] = [0u8; Signature::LENGTH];
        raw.copy_from_slice(&bytes[.. Signature::LENGTH]);

        Ok(Signature{raw: raw})
    }
}

fn compressed_point_from_bytes(bytes: &[u8]) -> Option<CompressedEdwardsY> {
    match <[u8; 32]>::try_from(&bytes[.. 32]) {
        Ok(x)  => return Some(CompressedEdwardsY(x)),
        Err(_) => return None
    }
}

fn point_from_bytes(bytes: &[u8]) -> Option<EdwardsPoint> {
    if let Some(point) = compressed_point_from_bytes(&bytes[..32]) {
        if let Some(x) =  point.decompress() {
            return Some(x);
        }
    }

    return None
}

fn scalar_from_bytes(bytes: &[u8]) -> Option<Scalar> {
    if bytes[31] & 224 != 0 {
        return None;
    }

    match <[u8; 32]>::try_from(&bytes[.. 32]) {
        Ok(x)  => return Some(Scalar::from_bits(x)),
        Err(_) => return None
    }
}
