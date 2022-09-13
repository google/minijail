// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A test of Minijail::fork_remap.
//!
//! It needs to be run on its own because it forks the process and by default cargo test is
//! multi-threaded, and we do not want copies of the other worker threads leaking into the child
//! process.

use std::fs::{read_link, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::path::Path;

use minijail::Minijail;

const DEV_NULL: &str = "/dev/null";
const DEV_ZERO: &str = "/dev/zero";
const PROC_CMDLINE: &str = "/proc/self/cmdline";

fn open_path(path: &str) -> Result<File, io::Error> {
    OpenOptions::new()
        .read(true)
        .write(false)
        .open(Path::new(path))
}

fn main() {
    let mut check_file1 = open_path(DEV_ZERO).unwrap();
    let mut check_file2 = open_path(PROC_CMDLINE).unwrap();
    let j = Minijail::new().unwrap();

    let mut stdio_expected = String::new();
    let mut file2_expected = String::new();
    for &p in &[0, 1, 2, check_file1.as_raw_fd(), check_file2.as_raw_fd()] {
        let path = format!("/proc/self/fd/{}", p);
        let target = read_link(Path::new(&path));
        eprintln!("P: {} -> {:?}", p, &target);
        if p == 2 {
            stdio_expected = target.unwrap().to_string_lossy().to_string();
        } else if p == check_file2.as_raw_fd() {
            file2_expected = target.unwrap().to_string_lossy().to_string();
        }
    }

    // Swap fd1 and fd2.
    let dest_fd1: RawFd = check_file2.as_raw_fd();
    let dest_fd2: RawFd = check_file1.as_raw_fd();

    if unsafe {
        j.fork_remap(&[
            // fd 0 tests stdio mapped to /dev/null.
            (2, 1),                              // One-to-many.
            (2, 2),                              // Identity.
            (check_file1.as_raw_fd(), dest_fd1), // Cross-over.
            (check_file2.as_raw_fd(), dest_fd2), // Cross-over.
        ])
    }
    .unwrap()
        != 0
    {
        j.wait().unwrap();
        eprintln!("Parent done.");
        return;
    }

    // Safe because we are re-taking ownership of remapped fds after forking.
    unsafe {
        check_file1.into_raw_fd();
        check_file1 = File::from_raw_fd(dest_fd1);

        check_file2.into_raw_fd();
        check_file2 = File::from_raw_fd(dest_fd2);
    }

    for (p, expected) in &[
        (0, DEV_NULL),
        (1, &stdio_expected),
        (2, &stdio_expected),
        (dest_fd1, DEV_ZERO),
        (dest_fd2, &file2_expected),
    ] {
        let path = format!("/proc/self/fd/{}", p);
        let target = read_link(Path::new(&path));
        eprintln!("  C: {} -> {:?}", p, &target);
        if !matches!(&target, Ok(p) if p == Path::new(expected)) {
            panic!("  C: got {:?}; expected Ok({:?})", target, expected);
        }
    }

    const BUFFER_LEN: usize = 16;
    let mut buffer = [0xffu8; BUFFER_LEN];
    check_file1.read_exact(&mut buffer).unwrap();
    assert_eq!(&buffer, &[0u8; BUFFER_LEN]);

    let mut file2_contents = Vec::<u8>::new();
    check_file2.read_to_end(&mut file2_contents).unwrap();

    eprintln!("  Child done.");
}
