// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// libminijail bindings for Rust.

#[allow(
    clippy::all,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]
mod libminijail {
    include!(concat!(env!("OUT_DIR"), "/libminijail.rs"));
}
pub use crate::libminijail::*;
