//! Internal interface
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2022 VTT Technical Research Centre of Finland Ltd


pub(crate) mod dispatcher;
pub(crate) mod ed25519;
pub(crate) mod utils;

#[cfg(feature = "debug_memory")]
pub(crate) mod alloc;
