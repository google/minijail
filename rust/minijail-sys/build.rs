// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Minijail's build script invoked by cargo.
///
/// This script prefers linking against a pkg-config provided libminijail, but will fall back to
/// building libminijail statically.
use std::env;
use std::fs::remove_file;
use std::io;
use std::path::Path;
use std::process::Command;

fn set_up_libminijail() -> io::Result<()> {
    // Minijail requires libcap at runtime.
    pkg_config::Config::new().probe("libcap").unwrap();

    // Prefer a system-provided Minijail library.
    if pkg_config::Config::new().probe("libminijail").is_ok() {
        return Ok(());
    }

    let current_dir = env::var("CARGO_MANIFEST_DIR").unwrap() + "/../..";
    let out_dir = env::var("OUT_DIR").unwrap();
    let profile = env::var("PROFILE").unwrap();

    let status = Command::new("make")
        .current_dir(&out_dir)
        .env("OUT", &out_dir)
        .env("MODE", if profile == "release" { "opt" } else { "debug" })
        .arg("-C")
        .arg(&current_dir)
        .arg("CC_STATIC_LIBRARY(libminijail.pic.a)")
        .status()?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    println!("cargo:rustc-link-search=native={}", &out_dir);
    println!("cargo:rustc-link-lib=static=minijail.pic");
    Ok(())
}

fn bindings_generation() -> io::Result<()> {
    let bindgen = match which::which("bindgen") {
        Ok(v) => v,
        // Use already generated copy if bindgen is not present.
        _ => return Ok(()),
    };

    // If CROS_RUST is set, skip generation.
    let gen_file = Path::new("./libminijail.rs");
    if gen_file.exists() {
        if env::var("CROS_RUST") == Ok(String::from("1")) {
            return Ok(());
        }
        remove_file(gen_file).expect("Failed to remove generated file.");
    }
    let header_dir = Path::new("../../");
    let header_path = header_dir.join("libminijail.h");
    println!("cargo:rerun-if-changed={}", header_path.display());
    let status = Command::new(&bindgen)
        .args(&["--default-enum-style", "rust"])
        .args(&["--blacklist-type", "__rlim64_t"])
        .args(&["--raw-line", "pub type __rlim64_t = u64;"])
        .args(&["--blacklist-type", "__u\\d{1,2}"])
        .args(&["--raw-line", "pub type __u8 = u8;"])
        .args(&["--raw-line", "pub type __u16 = u16;"])
        .args(&["--raw-line", "pub type __u32 = u32;"])
        .args(&["--blacklist-type", "__uint64_t"])
        .args(&["--whitelist-function", "^minijail_.*"])
        .args(&["--whitelist-var", "^MINIJAIL_.*"])
        .arg("--no-layout-tests")
        .args(&["--output", gen_file.to_str().unwrap()])
        .arg(header_path.to_str().unwrap())
        .args(&[
            "--",
            "-DUSE_BINDGEN",
            "-D_FILE_OFFSET_BITS=64",
            "-D_LARGEFILE_SOURCE",
            "-D_LARGEFILE64_SOURCE",
        ])
        .status()?;
    assert!(status.success());
    Ok(())
}

fn main() -> io::Result<()> {
    set_up_libminijail()?;
    bindings_generation()
}
