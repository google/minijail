// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Minijail's build script invoked by cargo.
///
/// This script prefers linking against a pkg-config provided libminijail, but will fall back to
/// building libminijail statically.
use std::env;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use bindgen::EnumVariation;

const HEADER_FILENAME: &str = "libminijail.h";
const OUT_FILENAME: &str = "libminijail.rs";

/// Returns the target triplet prefix for gcc commands. No prefix is required
/// for native builds.
fn get_cross_compile_prefix() -> String {
    if let Ok(cross_compile) = env::var("CROSS_COMPILE") {
        return cross_compile;
    }

    let target = env::var("TARGET").unwrap();

    if env::var("HOST").unwrap() == target {
        return String::from("");
    }

    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let env = if target.ends_with("-gnueabihf") {
        String::from("gnueabihf")
    } else {
        env::var("CARGO_CFG_TARGET_ENV").unwrap()
    };
    return format!("{}-{}-{}-", arch, os, env);
}

fn set_up_libminijail() -> io::Result<PathBuf> {
    // Minijail requires libcap at runtime.
    pkg_config::Config::new().probe("libcap").unwrap();

    // Prefer a system-provided Minijail library.
    if let Ok(info) = pkg_config::Config::new().probe("libminijail") {
        for path in info.include_paths {
            let header_path = path.join(HEADER_FILENAME);
            if header_path.exists() {
                return Ok(header_path);
            }
        }
    }

    let current_dir = env::var("CARGO_MANIFEST_DIR").unwrap() + "/../..";
    let out_dir = env::var("OUT_DIR").unwrap();
    let profile = env::var("PROFILE").unwrap();

    let status = Command::new("make")
        .current_dir(&out_dir)
        .env("OUT", &out_dir)
        .env("MODE", if profile == "release" { "opt" } else { "debug" })
        .env("CROSS_COMPILE", get_cross_compile_prefix())
        .env("BUILD_STATIC_LIBS", "yes")
        .arg("-C")
        .arg(&current_dir)
        .status()?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    println!("cargo:rustc-link-search=native={}", &out_dir);
    println!("cargo:rustc-link-lib=static=minijail.pic");

    let header_dir = Path::new("../../");
    let header_path = header_dir.join(HEADER_FILENAME);
    Ok(header_path)
}

fn bindings_generation(header_path: &str) -> io::Result<()> {
    println!("cargo:rerun-if-changed={}", header_path);
    println!("cargo:rerun-if-changed=build.rs");

    let bindings = bindgen::Builder::default()
        .header(header_path)
        .default_enum_style(EnumVariation::Rust {
            non_exhaustive: false,
        })
        .blocklist_type("__rlim64_t")
        .raw_line("pub type __rlim64_t = u64;")
        .blocklist_type("__u\\d{1,2}")
        .raw_line("pub type __u8 = u8;")
        .raw_line("pub type __u16 = u16;")
        .raw_line("pub type __u32 = u32;")
        .blocklist_type("__uint64_t")
        .allowlist_function("^minijail_.*")
        .allowlist_var("^MINIJAIL_.*")
        .size_t_is_usize(true)
        .layout_tests(false)
        .disable_header_comment()
        .clang_arg("-DUSE_BINDGEN")
        .clang_arg("-D_FILE_OFFSET_BITS=64")
        .clang_arg("-D_LARGEFILE_SOURCE")
        .clang_arg("-D_LARGEFILE64_SOURCE")
        .generate()
        .expect("failed to generate bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out_path.join(OUT_FILENAME))
}

fn main() -> io::Result<()> {
    let header_path = set_up_libminijail()?;
    bindings_generation(header_path.to_str().unwrap())
}
