// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// libminijail bindings for Rust.

// TODO(crbug.com/1032672): Generate bindings at build time.
//
// Bindgen will invoke the C preprocessor to process headers, which means that the bindings
// generated can depend on the architecture that actually ran bindgen. In particular, for
// portability across compilers glibc defines types like __u8 and __rlim64_t in terms of C types
// like unsigned char and unsigned long. This is problematic for __rlim64_t since that resolves to
// unsigned long int on amd64, which will end up being 32-bit on 32-bit platforms.
//
// As a workaround to let us commit these bindings and still use them on 32-bit platforms, the
// bindgen invocation blacklists some of the generated fixed-width types and redefines them
// manually as Rust fixed-width types.
//
// Generated in CrOS SDK chroot with:
// bindgen --default-enum-style rust \
//         --blacklist-type '__rlim64_t' \
//         --raw-line 'pub type __rlim64_t = u64;' \
//         --blacklist-type '__u\d{1,2}' \
//         --raw-line 'pub type __u8 = u8;' \
//         --raw-line 'pub type __u16 = u16;' \
//         --raw-line 'pub type __u32 = u32;' \
//         --blacklist-type '__uint64_t' \
//         --whitelist-function '^minijail_.*' \
//         --whitelist-var '^MINIJAIL_.*' \
//         --no-layout-tests \
//         --output libminijail.rs \
//         libminijail.h -- \
//         -DUSE_BINDGEN \
//         -D_FILE_OFFSET_BITS=64 \
//         -D_LARGEFILE_SOURCE \
//         -D_LARGEFILE64_SOURCE
//
// Enum variants in rust are customarily camel case, but bindgen will leave the original names
// intact.
#[allow(non_camel_case_types)]
mod libminijail;
pub use crate::libminijail::*;
