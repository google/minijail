// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A test of Minijail::fork_remap.
//!
//! It needs to be run on its own because it forks the process and by default cargo test is
//! multi-threaded, and we do not want copies of the other worker threads leaking into the child
//! process.

use std::fs::{read_link, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;

use minijail::Minijail;

const DEV_NULL: &str = "/dev/null";
const DEV_ZERO: &str = "/dev/zero";

const DEST_FD1: RawFd = 7;
const DEST_FD2: RawFd = 8;

fn open_dev_zero() -> Result<File, io::Error> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(Path::new(DEV_ZERO))
}

fn main() {
    let mut check_file1 = open_dev_zero().unwrap();
    let mut check_file2 = open_dev_zero().unwrap();
    let j = Minijail::new().unwrap();

    for p in &[0, 1, check_file1.as_raw_fd(), check_file2.as_raw_fd()] {
        let path = format!("/proc/self/fd/{}", p);
        let target = read_link(Path::new(&path));
        eprintln!("P: {} -> {:?}", p, &target);
    }

    if unsafe {
        j.fork_remap(&[
            (2, 2),
            (check_file1.as_raw_fd(), DEST_FD1),
            (check_file2.as_raw_fd(), DEST_FD2),
        ])
    }
    .unwrap()
        != 0
    {
        j.wait().unwrap();
        eprintln!("Parent done.");
        return;
    }

    // Safe because we are re-taking ownership of a remapped fd after forking.
    check_file1 = unsafe { File::from_raw_fd(DEST_FD1) };
    check_file2 = unsafe { File::from_raw_fd(DEST_FD2) };

    for (p, expected) in &[
        (0, DEV_NULL),
        (1, DEV_NULL),
        (DEST_FD1, DEV_ZERO),
        (DEST_FD2, DEV_ZERO),
    ] {
        let path = format!("/proc/self/fd/{}", p);
        let target = read_link(Path::new(&path));
        eprintln!("C: {} -> {:?}", p, &target);
        if !matches!(&target, Ok(p) if p == Path::new(expected)) {
            panic!("C: got {:?}; expected Ok({:?})", target, expected);
        }
    }

    const BUFFER_LEN: usize = 16;
    let mut buffer = [0xffu8; BUFFER_LEN];
    check_file1.read_exact(&mut buffer).unwrap();
    assert_eq!(&buffer, &[0u8; BUFFER_LEN]);

    eprintln!("Child done.");
}
