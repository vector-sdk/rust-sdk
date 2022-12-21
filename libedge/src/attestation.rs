//! Definitions for attestation parameters
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd


/// Maximum length of caller-specified nonce in bytes
pub const NONCE_MAX_LENGTH: usize = 1024; /* This comes from Keystone */

/// Maximum length of the attestation report in bytes.
pub const REPORT_MAX_LENGTH: usize = 2048; /* This comes from Keystone */
