// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CString;
use std::fmt::{self, Display};
use std::fs;
use std::io;
use std::os::raw::{c_char, c_ulong, c_ushort};
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::result::Result as StdResult;

use libc::pid_t;
use minijail_sys::*;

enum Program {
    Filename(PathBuf),
    FileDescriptor(RawFd),
}

/// Configuration of a command to be run in a jail.
pub struct Command {
    program: Program,
    preserve_fds: Vec<(RawFd, RawFd)>,

    // Ownership of the backing data of args_cptr is provided by args_cstr.
    args_cstr: Vec<CString>,
    args_cptr: Vec<*const c_char>,

    // Ownership of the backing data of env_cptr is provided by env_cstr.
    env_cstr: Option<Vec<CString>>,
    env_cptr: Option<Vec<*const c_char>>,
}

impl Command {
    /// This exposes a subset of what Command can do, before we are ready to commit to a stable
    /// API.
    pub fn new_for_path<P: AsRef<Path>, S: AsRef<str>, A: AsRef<str>>(
        path: P,
        keep_fds: &[RawFd],
        args: &[S],
        env_vars: Option<&[A]>,
    ) -> Result<Command> {
        let mut cmd = Command::new(Program::Filename(path.as_ref().to_path_buf()))
            .keep_fds(keep_fds)
            .args(args)?;
        if let Some(env_vars) = env_vars {
            cmd = cmd.envs(env_vars)?;
        }

        Ok(cmd)
    }

    fn new(program: Program) -> Command {
        Command {
            program,
            preserve_fds: Vec::new(),
            args_cstr: Vec::new(),
            args_cptr: Vec::new(),
            env_cstr: None,
            env_cptr: None,
        }
    }

    fn keep_fds(mut self, keep_fds: &[RawFd]) -> Command {
        self.preserve_fds = keep_fds
            .iter()
            .map(|&a| (a, a))
            .collect::<Vec<(RawFd, RawFd)>>();
        self
    }

    fn remap_fds(mut self, remap_fds: &[(RawFd, RawFd)]) -> Command {
        self.preserve_fds = remap_fds.to_vec();
        self
    }

    fn args<S: AsRef<str>>(mut self, args: &[S]) -> Result<Command> {
        let (args_cstr, args_cptr) = to_execve_cstring_array(args)?;
        self.args_cstr = args_cstr;
        self.args_cptr = args_cptr;
        Ok(self)
    }

    fn envs<S: AsRef<str>>(mut self, vars: &[S]) -> Result<Command> {
        let (env_cstr, env_cptr) = to_execve_cstring_array(vars)?;
        self.env_cstr = Some(env_cstr);
        self.env_cptr = Some(env_cptr);
        Ok(self)
    }

    fn argv(&self) -> *const *mut c_char {
        self.args_cptr.as_ptr() as *const *mut c_char
    }

    fn envp(&self) -> *const *mut c_char {
        (match self.env_cptr {
            Some(ref env_cptr) => env_cptr.as_ptr(),
            None => null_mut(),
        }) as *const *mut c_char
    }
}

/// Abstracts paths and executable file descriptors in a way that the run implementation can cover
/// both.
trait Runnable {
    fn run_command(&self, jail: &Minijail, cmd: &Command) -> Result<pid_t>;
}

impl Runnable for &Path {
    fn run_command(&self, jail: &Minijail, cmd: &Command) -> Result<pid_t> {
        let path_str = self
            .to_str()
            .ok_or_else(|| Error::PathToCString(self.to_path_buf()))?;
        let path_cstr =
            CString::new(path_str).map_err(|_| Error::StrToCString(path_str.to_owned()))?;

        let mut pid: pid_t = 0;
        let ret = unsafe {
            minijail_run_env_pid_pipes(
                jail.jail,
                path_cstr.as_ptr(),
                cmd.argv(),
                cmd.envp(),
                &mut pid,
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if ret < 0 {
            return Err(Error::ForkingMinijail(ret));
        }
        Ok(pid)
    }
}

impl Runnable for RawFd {
    fn run_command(&self, jail: &Minijail, cmd: &Command) -> Result<pid_t> {
        let mut pid: pid_t = 0;
        let ret = unsafe {
            minijail_run_fd_env_pid_pipes(
                jail.jail,
                *self,
                cmd.argv(),
                cmd.envp(),
                &mut pid,
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if ret < 0 {
            return Err(Error::ForkingMinijail(ret));
        }
        Ok(pid)
    }
}

#[derive(Debug)]
pub enum Error {
    // minijail failed to accept bind mount.
    BindMount {
        errno: i32,
        src: PathBuf,
        dst: PathBuf,
    },
    // minijail failed to accept mount.
    Mount {
        errno: i32,
        src: PathBuf,
        dest: PathBuf,
        fstype: String,
        flags: usize,
        data: String,
    },
    /// Failure to count the number of threads in /proc/self/tasks.
    CheckingMultiThreaded(io::Error),
    /// minjail_new failed, this is an allocation failure.
    CreatingMinijail,
    /// minijail_fork failed with the given error code.
    ForkingMinijail(i32),
    /// Attempt to `fork` while already multithreaded.
    ForkingWhileMultiThreaded,
    /// The seccomp policy path doesn't exist.
    SeccompPath(PathBuf),
    /// The string passed in didn't parse to a valid CString.
    StrToCString(String),
    /// The path passed in didn't parse to a valid CString.
    PathToCString(PathBuf),
    /// Failed to call dup2 to set stdin, stdout, or stderr to /dev/null.
    DupDevNull(i32),
    /// Failed to set up /dev/null for FDs 0, 1, or 2.
    OpenDevNull(io::Error),
    /// Failed to read policy bpf from file.
    ReadProgram(io::Error),
    /// Setting the specified alt-syscall table failed with errno. Is the table in the kernel?
    SetAltSyscallTable { errno: i32, name: String },
    /// Setting the specified rlimit failed with errno.
    SetRlimit { errno: i32, kind: libc::c_int },
    /// chroot failed with the provided errno.
    SettingChrootDirectory(i32, PathBuf),
    /// pivot_root failed with the provided errno.
    SettingPivotRootDirectory(i32, PathBuf),
    /// There is an entry in /proc/self/fd that isn't a valid PID.
    ReadFdDirEntry(io::Error),
    /// /proc/self/fd failed to open.
    ReadFdDir(io::Error),
    /// An entry in /proc/self/fd is not an integer
    ProcFd(String),
    /// Minijail refused to preserve an FD in the inherit list of `fork()`.
    PreservingFd(i32),
    /// Program size is too large
    ProgramTooLarge,
    /// Alignment of file should be divisible by the alignment of sock_filter.
    WrongProgramAlignment,
    /// File size should be non-zero and a multiple of sock_filter
    WrongProgramSize,

    /// The command was not found.
    NoCommand,
    /// The command could not be run.
    NoAccess,
    /// Process was killed by SIGSYS indicating a seccomp violation.
    SeccompViolation(i32),
    /// Process was killed by a signal other than SIGSYS.
    Killed(u8),
    /// Process finished returning a non-zero code.
    ReturnCode(u8),
    /// Failed to wait the process.
    Wait(i32),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            BindMount { src, dst, errno } => write!(
                f,
                "failed to accept bind mount {} -> {}: {}",
                src.display(),
                dst.display(),
                io::Error::from_raw_os_error(*errno),
            ),
            Mount {
                errno,
                src,
                dest,
                fstype,
                flags,
                data,
            } => write!(
                f,
                "failed to accept mount {} -> {} of type {:?} with flags 0x{:x} \
                 and data {:?}: {}",
                src.display(),
                dest.display(),
                fstype,
                flags,
                data,
                io::Error::from_raw_os_error(*errno),
            ),
            CheckingMultiThreaded(e) => write!(
                f,
                "Failed to count the number of threads from /proc/self/tasks {}",
                e
            ),
            CreatingMinijail => write!(f, "minjail_new failed due to an allocation failure"),
            ForkingMinijail(e) => write!(f, "minijail_fork failed with error {}", e),
            ForkingWhileMultiThreaded => write!(f, "Attempt to call fork() while multithreaded"),
            SeccompPath(p) => write!(f, "missing seccomp policy path: {}", p.display()),
            StrToCString(s) => write!(f, "failed to convert string into CString: {}", s),
            PathToCString(s) => write!(f, "failed to convert path into CString: {}", s.display()),
            DupDevNull(errno) => write!(
                f,
                "failed to call dup2 to set stdin, stdout, or stderr to /dev/null: {}",
                io::Error::from_raw_os_error(*errno),
            ),
            OpenDevNull(e) => write!(
                f,
                "fail to open /dev/null for setting FDs 0, 1, or 2: {}",
                e,
            ),
            ReadProgram(e) => write!(f, "failed to read from bpf file: {}", e),
            SetAltSyscallTable { name, errno } => write!(
                f,
                "failed to set alt-syscall table {}: {}",
                name,
                io::Error::from_raw_os_error(*errno),
            ),
            SetRlimit { errno, kind } => write!(f, "failed to set rlimit {}: {}", kind, errno),
            SettingChrootDirectory(errno, p) => write!(
                f,
                "failed to set chroot {}: {}",
                p.display(),
                io::Error::from_raw_os_error(*errno),
            ),
            SettingPivotRootDirectory(errno, p) => write!(
                f,
                "failed to set pivot root {}: {}",
                p.display(),
                io::Error::from_raw_os_error(*errno),
            ),
            ReadFdDirEntry(e) => write!(f, "failed to read an entry in /proc/self/fd: {}", e),
            ReadFdDir(e) => write!(f, "failed to open /proc/self/fd: {}", e),
            ProcFd(s) => write!(f, "an entry in /proc/self/fd is not an integer: {}", s),
            PreservingFd(e) => write!(f, "fork failed in minijail_preserve_fd with error {}", e),
            ProgramTooLarge => write!(f, "bpf program is too large (max 64K instructions)"),
            WrongProgramAlignment => write!(
                f,
                "the alignment of bpf file was not a multiple of that of sock_filter"
            ),
            WrongProgramSize => write!(f, "bpf file was empty or not a multiple of sock_filter"),
            NoCommand => write!(f, "command was not found"),
            NoAccess => write!(f, "unable to execute command"),
            SeccompViolation(s) => write!(f, "seccomp violation syscall #{}", s),
            Killed(s) => write!(f, "killed with signal number {}", s),
            ReturnCode(e) => write!(f, "exited with code {}", e),
            Wait(errno) => write!(
                f,
                "failed to wait: {}",
                io::Error::from_raw_os_error(*errno)
            ),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = StdResult<T, Error>;

/// Configuration to jail a process based on wrapping libminijail.
///
/// Intentionally leave out everything related to `minijail_run`.  Forking is
/// hard to reason about w.r.t. memory and resource safety.  It is better to avoid
/// forking from rust code.  Leave forking to the library user, who can make
/// an informed decision about when to fork to minimize risk.
/// # Examples
/// * Load seccomp policy - like "minijail0 -n -S myfilter.policy"
///
/// ```
/// # use minijail::Minijail;
/// # fn seccomp_filter_test() -> Result<(), ()> {
///       let mut j = Minijail::new().map_err(|_| ())?;
///       j.no_new_privs();
///       j.parse_seccomp_filters("my_filter.policy").map_err(|_| ())?;
///       j.use_seccomp_filter();
///       unsafe { // `fork` will close all the programs FDs.
///           j.fork(None).map_err(|_| ())?;
///       }
/// #     Ok(())
/// # }
/// ```
///
/// * Keep stdin, stdout, and stderr open after jailing.
///
/// ```
/// # use minijail::Minijail;
/// # use std::os::unix::io::RawFd;
/// # fn seccomp_filter_test() -> Result<(), ()> {
///       let j = Minijail::new().map_err(|_| ())?;
///       let preserve_fds: Vec<RawFd> = vec![0, 1, 2];
///       unsafe { // `fork` will close all the programs FDs.
///           j.fork(Some(&preserve_fds)).map_err(|_| ())?;
///       }
/// #     Ok(())
/// # }
/// ```
/// # Errors
/// The `fork` function might not return an error if it fails after forking. A
/// partial jail is not recoverable and will instead result in killing the
/// process.
pub struct Minijail {
    jail: *mut minijail,
}

#[link(name = "c")]
extern "C" {
    fn __libc_current_sigrtmax() -> libc::c_int;
}

fn translate_wait_error(ret: libc::c_int) -> Result<()> {
    if ret == 0 {
        return Ok(());
    }
    if ret < 0 {
        return Err(Error::Wait(ret));
    }
    if ret == MINIJAIL_ERR_NO_COMMAND as libc::c_int {
        return Err(Error::NoCommand);
    }
    if ret == MINIJAIL_ERR_NO_ACCESS as libc::c_int {
        return Err(Error::NoAccess);
    }
    let sig_base: libc::c_int = MINIJAIL_ERR_SIG_BASE as libc::c_int;
    let sig_max_code: libc::c_int = unsafe { __libc_current_sigrtmax() } + sig_base;
    if ret > sig_base && ret <= sig_max_code {
        return Err(Error::Killed(
            (ret - MINIJAIL_ERR_SIG_BASE as libc::c_int) as u8,
        ));
    }
    if ret > 0 && ret <= 0xff {
        return Err(Error::ReturnCode(ret as u8));
    }
    unreachable!("Unexpected returned value from wait: {}", ret);
}

impl Minijail {
    /// Creates a new jail configuration.
    pub fn new() -> Result<Minijail> {
        let j = unsafe {
            // libminijail actually owns the minijail structure. It will live until we call
            // minijail_destroy.
            minijail_new()
        };
        if j.is_null() {
            return Err(Error::CreatingMinijail);
        }
        Ok(Minijail { jail: j })
    }

    /// Clones self to a new `Minijail`. Useful because `fork` can only be called once on a
    /// `Minijail`.
    pub fn try_clone(&self) -> Result<Minijail> {
        let jail_out = Minijail::new()?;
        unsafe {
            // Safe to clone one minijail to the other as minijail_clone doesn't modify the source
            // jail(`self`) and leaves a valid minijail in the destination(`jail_out`).
            let ret = minijail_copy_jail(self.jail, jail_out.jail);
            if ret < 0 {
                return Err(Error::ReturnCode(ret as u8));
            }
        }

        Ok(jail_out)
    }

    // The following functions are safe because they only set values in the
    // struct already owned by minijail.  The struct's lifetime is tied to
    // `struct Minijail` so it is guaranteed to be valid

    pub fn change_uid(&mut self, uid: libc::uid_t) {
        unsafe {
            minijail_change_uid(self.jail, uid);
        }
    }
    pub fn change_gid(&mut self, gid: libc::gid_t) {
        unsafe {
            minijail_change_gid(self.jail, gid);
        }
    }
    pub fn change_user(&mut self, user: &str) -> Result<()> {
        let user_cstring = CString::new(user).map_err(|_| Error::StrToCString(user.to_owned()))?;
        unsafe {
            minijail_change_user(self.jail, user_cstring.as_ptr());
        }
        Ok(())
    }
    pub fn change_group(&mut self, group: &str) -> Result<()> {
        let group_cstring =
            CString::new(group).map_err(|_| Error::StrToCString(group.to_owned()))?;
        unsafe {
            minijail_change_group(self.jail, group_cstring.as_ptr());
        }
        Ok(())
    }
    pub fn set_supplementary_gids(&mut self, ids: &[libc::gid_t]) {
        unsafe {
            minijail_set_supplementary_gids(self.jail, ids.len(), ids.as_ptr());
        }
    }
    pub fn keep_supplementary_gids(&mut self) {
        unsafe {
            minijail_keep_supplementary_gids(self.jail);
        }
    }
    // rlim_t is defined in minijail-sys to be u64 on all platforms, to avoid
    // issues on 32-bit platforms. It's also useful to us here to avoid
    // libc::rlim64_t, which is not defined at all on Android.
    pub fn set_rlimit(&mut self, kind: libc::c_int, cur: rlim_t, max: rlim_t) -> Result<()> {
        let errno = unsafe { minijail_rlimit(self.jail, kind, cur, max) };
        if errno == 0 {
            Ok(())
        } else {
            Err(Error::SetRlimit { errno, kind })
        }
    }
    pub fn use_seccomp(&mut self) {
        unsafe {
            minijail_use_seccomp(self.jail);
        }
    }
    pub fn no_new_privs(&mut self) {
        unsafe {
            minijail_no_new_privs(self.jail);
        }
    }
    pub fn use_seccomp_filter(&mut self) {
        unsafe {
            minijail_use_seccomp_filter(self.jail);
        }
    }
    pub fn set_seccomp_filter_tsync(&mut self) {
        unsafe {
            minijail_set_seccomp_filter_tsync(self.jail);
        }
    }
    pub fn parse_seccomp_program<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        if !path.as_ref().is_file() {
            return Err(Error::SeccompPath(path.as_ref().to_owned()));
        }

        let buffer = fs::read(path).map_err(Error::ReadProgram)?;
        self.parse_seccomp_bytes(&buffer)
    }
    pub fn parse_seccomp_bytes(&mut self, buffer: &[u8]) -> Result<()> {
        if buffer.len() % std::mem::size_of::<sock_filter>() != 0 {
            return Err(Error::WrongProgramSize);
        }
        let count = buffer.len() / std::mem::size_of::<sock_filter>();
        if count > (!0 as u16) as usize {
            return Err(Error::ProgramTooLarge);
        }
        if buffer.as_ptr() as usize % std::mem::align_of::<sock_filter>() != 0 {
            return Err(Error::WrongProgramAlignment);
        }

        // Safe cast because we checked that the buffer address is divisible by the alignment of
        // sock_filter.
        #[allow(clippy::cast_ptr_alignment)]
        let header = sock_fprog {
            len: count as c_ushort,
            filter: buffer.as_ptr() as *mut sock_filter,
        };
        unsafe {
            minijail_set_seccomp_filters(self.jail, &header);
        }
        Ok(())
    }
    pub fn parse_seccomp_filters<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        if !path.as_ref().is_file() {
            return Err(Error::SeccompPath(path.as_ref().to_owned()));
        }

        let pathstring = path
            .as_ref()
            .as_os_str()
            .to_str()
            .ok_or_else(|| Error::PathToCString(path.as_ref().to_owned()))?;
        let filename =
            CString::new(pathstring).map_err(|_| Error::PathToCString(path.as_ref().to_owned()))?;
        unsafe {
            minijail_parse_seccomp_filters(self.jail, filename.as_ptr());
        }
        Ok(())
    }
    pub fn log_seccomp_filter_failures(&mut self) {
        unsafe {
            minijail_log_seccomp_filter_failures(self.jail);
        }
    }
    pub fn use_caps(&mut self, capmask: u64) {
        unsafe {
            minijail_use_caps(self.jail, capmask);
        }
    }
    pub fn capbset_drop(&mut self, capmask: u64) {
        unsafe {
            minijail_capbset_drop(self.jail, capmask);
        }
    }
    pub fn set_ambient_caps(&mut self) {
        unsafe {
            minijail_set_ambient_caps(self.jail);
        }
    }
    pub fn reset_signal_mask(&mut self) {
        unsafe {
            minijail_reset_signal_mask(self.jail);
        }
    }
    pub fn run_as_init(&mut self) {
        unsafe {
            minijail_run_as_init(self.jail);
        }
    }
    pub fn namespace_pids(&mut self) {
        unsafe {
            minijail_namespace_pids(self.jail);
        }
    }
    pub fn namespace_user(&mut self) {
        unsafe {
            minijail_namespace_user(self.jail);
        }
    }
    pub fn namespace_user_disable_setgroups(&mut self) {
        unsafe {
            minijail_namespace_user_disable_setgroups(self.jail);
        }
    }
    pub fn namespace_vfs(&mut self) {
        unsafe {
            minijail_namespace_vfs(self.jail);
        }
    }
    pub fn new_session_keyring(&mut self) {
        unsafe {
            minijail_new_session_keyring(self.jail);
        }
    }
    pub fn skip_remount_private(&mut self) {
        unsafe {
            minijail_skip_remount_private(self.jail);
        }
    }
    pub fn namespace_ipc(&mut self) {
        unsafe {
            minijail_namespace_ipc(self.jail);
        }
    }
    pub fn namespace_net(&mut self) {
        unsafe {
            minijail_namespace_net(self.jail);
        }
    }
    pub fn namespace_cgroups(&mut self) {
        unsafe {
            minijail_namespace_cgroups(self.jail);
        }
    }
    pub fn remount_proc_readonly(&mut self) {
        unsafe {
            minijail_remount_proc_readonly(self.jail);
        }
    }
    pub fn set_remount_mode(&mut self, mode: c_ulong) {
        unsafe { minijail_remount_mode(self.jail, mode) }
    }
    pub fn uidmap(&mut self, uid_map: &str) -> Result<()> {
        let map_cstring =
            CString::new(uid_map).map_err(|_| Error::StrToCString(uid_map.to_owned()))?;
        unsafe {
            minijail_uidmap(self.jail, map_cstring.as_ptr());
        }
        Ok(())
    }
    pub fn gidmap(&mut self, gid_map: &str) -> Result<()> {
        let map_cstring =
            CString::new(gid_map).map_err(|_| Error::StrToCString(gid_map.to_owned()))?;
        unsafe {
            minijail_gidmap(self.jail, map_cstring.as_ptr());
        }
        Ok(())
    }
    pub fn inherit_usergroups(&mut self) {
        unsafe {
            minijail_inherit_usergroups(self.jail);
        }
    }
    pub fn use_alt_syscall(&mut self, table_name: &str) -> Result<()> {
        let table_name_string =
            CString::new(table_name).map_err(|_| Error::StrToCString(table_name.to_owned()))?;
        let ret = unsafe { minijail_use_alt_syscall(self.jail, table_name_string.as_ptr()) };
        if ret < 0 {
            return Err(Error::SetAltSyscallTable {
                errno: ret,
                name: table_name.to_owned(),
            });
        }
        Ok(())
    }
    pub fn enter_chroot<P: AsRef<Path>>(&mut self, dir: P) -> Result<()> {
        let pathstring = dir
            .as_ref()
            .as_os_str()
            .to_str()
            .ok_or_else(|| Error::PathToCString(dir.as_ref().to_owned()))?;
        let dirname =
            CString::new(pathstring).map_err(|_| Error::PathToCString(dir.as_ref().to_owned()))?;
        let ret = unsafe { minijail_enter_chroot(self.jail, dirname.as_ptr()) };
        if ret < 0 {
            return Err(Error::SettingChrootDirectory(ret, dir.as_ref().to_owned()));
        }
        Ok(())
    }
    pub fn enter_pivot_root<P: AsRef<Path>>(&mut self, dir: P) -> Result<()> {
        let pathstring = dir
            .as_ref()
            .as_os_str()
            .to_str()
            .ok_or_else(|| Error::PathToCString(dir.as_ref().to_owned()))?;
        let dirname =
            CString::new(pathstring).map_err(|_| Error::PathToCString(dir.as_ref().to_owned()))?;
        let ret = unsafe { minijail_enter_pivot_root(self.jail, dirname.as_ptr()) };
        if ret < 0 {
            return Err(Error::SettingPivotRootDirectory(
                ret,
                dir.as_ref().to_owned(),
            ));
        }
        Ok(())
    }
    pub fn mount<P1: AsRef<Path>, P2: AsRef<Path>>(
        &mut self,
        src: P1,
        dest: P2,
        fstype: &str,
        flags: usize,
    ) -> Result<()> {
        self.mount_with_data(src, dest, fstype, flags, "")
    }
    pub fn mount_with_data<P1: AsRef<Path>, P2: AsRef<Path>>(
        &mut self,
        src: P1,
        dest: P2,
        fstype: &str,
        flags: usize,
        data: &str,
    ) -> Result<()> {
        let src_os = src
            .as_ref()
            .as_os_str()
            .to_str()
            .ok_or_else(|| Error::PathToCString(src.as_ref().to_owned()))?;
        let src_path = CString::new(src_os).map_err(|_| Error::StrToCString(src_os.to_owned()))?;
        let dest_os = dest
            .as_ref()
            .as_os_str()
            .to_str()
            .ok_or_else(|| Error::PathToCString(dest.as_ref().to_owned()))?;
        let dest_path =
            CString::new(dest_os).map_err(|_| Error::StrToCString(dest_os.to_owned()))?;
        let fstype_string =
            CString::new(fstype).map_err(|_| Error::StrToCString(fstype.to_owned()))?;
        let data_string = CString::new(data).map_err(|_| Error::StrToCString(data.to_owned()))?;
        let ret = unsafe {
            minijail_mount_with_data(
                self.jail,
                src_path.as_ptr(),
                dest_path.as_ptr(),
                fstype_string.as_ptr(),
                flags as _,
                data_string.as_ptr(),
            )
        };
        if ret < 0 {
            return Err(Error::Mount {
                errno: ret,
                src: src.as_ref().to_owned(),
                dest: dest.as_ref().to_owned(),
                fstype: fstype.to_owned(),
                flags,
                data: data.to_owned(),
            });
        }
        Ok(())
    }
    pub fn mount_dev(&mut self) {
        unsafe {
            minijail_mount_dev(self.jail);
        }
    }
    pub fn mount_tmp(&mut self) {
        unsafe {
            minijail_mount_tmp(self.jail);
        }
    }
    pub fn mount_tmp_size(&mut self, size: usize) {
        unsafe {
            minijail_mount_tmp_size(self.jail, size);
        }
    }
    pub fn mount_bind<P1: AsRef<Path>, P2: AsRef<Path>>(
        &mut self,
        src: P1,
        dest: P2,
        writable: bool,
    ) -> Result<()> {
        let src_os = src
            .as_ref()
            .as_os_str()
            .to_str()
            .ok_or_else(|| Error::PathToCString(src.as_ref().to_owned()))?;
        let src_path = CString::new(src_os).map_err(|_| Error::StrToCString(src_os.to_owned()))?;
        let dest_os = dest
            .as_ref()
            .as_os_str()
            .to_str()
            .ok_or_else(|| Error::PathToCString(dest.as_ref().to_owned()))?;
        let dest_path =
            CString::new(dest_os).map_err(|_| Error::StrToCString(dest_os.to_owned()))?;
        let ret = unsafe {
            minijail_bind(
                self.jail,
                src_path.as_ptr(),
                dest_path.as_ptr(),
                writable as _,
            )
        };
        if ret < 0 {
            return Err(Error::BindMount {
                errno: ret,
                src: src.as_ref().to_owned(),
                dst: dest.as_ref().to_owned(),
            });
        }
        Ok(())
    }

    /// Forks and execs a child and puts it in the previously configured minijail.
    /// FDs 0, 1, and 2 are overwritten with /dev/null FDs unless they are included in the
    /// inheritable_fds list. This function may abort in the child on error because a partially
    /// entered jail isn't recoverable.
    pub fn run<P: AsRef<Path>, S: AsRef<str>>(
        &self,
        cmd: P,
        inheritable_fds: &[RawFd],
        args: &[S],
    ) -> Result<pid_t> {
        self.run_internal(
            Command::new(Program::Filename(cmd.as_ref().to_path_buf()))
                .keep_fds(inheritable_fds)
                .args(args)?,
        )
    }

    /// Behaves the same as `run()` except `inheritable_fds` is a list of fd
    /// mappings rather than just a list of fds to preserve.
    pub fn run_remap<P: AsRef<Path>, S: AsRef<str>>(
        &self,
        cmd: P,
        inheritable_fds: &[(RawFd, RawFd)],
        args: &[S],
    ) -> Result<pid_t> {
        self.run_internal(
            Command::new(Program::Filename(cmd.as_ref().to_path_buf()))
                .remap_fds(inheritable_fds)
                .args(args)?,
        )
    }

    /// Behaves the same as `run()` except cmd is a file descriptor to the executable.
    pub fn run_fd<F: AsRawFd, S: AsRef<str>>(
        &self,
        cmd: &F,
        inheritable_fds: &[RawFd],
        args: &[S],
    ) -> Result<pid_t> {
        self.run_internal(
            Command::new(Program::FileDescriptor(cmd.as_raw_fd()))
                .keep_fds(inheritable_fds)
                .args(args)?,
        )
    }

    /// Behaves the same as `run()` except cmd is a file descriptor to the executable, and
    /// `inheritable_fds` is a list of fd mappings rather than just a list of fds to preserve.
    pub fn run_fd_remap<F: AsRawFd, S: AsRef<str>>(
        &self,
        cmd: &F,
        inheritable_fds: &[(RawFd, RawFd)],
        args: &[S],
    ) -> Result<pid_t> {
        self.run_internal(
            Command::new(Program::FileDescriptor(cmd.as_raw_fd()))
                .remap_fds(inheritable_fds)
                .args(args)?,
        )
    }

    /// A generic version of `run()` that is a super set of all variants.
    pub fn run_command(&self, cmd: Command) -> Result<pid_t> {
        self.run_internal(cmd)
    }

    fn run_internal(&self, cmd: Command) -> Result<pid_t> {
        for (src_fd, dst_fd) in cmd.preserve_fds.iter() {
            let ret = unsafe { minijail_preserve_fd(self.jail, *src_fd, *dst_fd) };
            if ret < 0 {
                return Err(Error::PreservingFd(ret));
            }
        }

        let dev_null = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .map_err(Error::OpenDevNull)?;
        // Set stdin, stdout, and stderr to /dev/null unless they are in the inherit list.
        // These will only be closed when this process exits.
        for io_fd in &[libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            if !cmd.preserve_fds.iter().any(|(_, fd)| *fd == *io_fd) {
                let ret = unsafe { minijail_preserve_fd(self.jail, dev_null.as_raw_fd(), *io_fd) };
                if ret < 0 {
                    return Err(Error::PreservingFd(ret));
                }
            }
        }

        unsafe {
            minijail_close_open_fds(self.jail);
        }

        match cmd.program {
            Program::Filename(ref path) => path.as_path().run_command(self, &cmd),
            Program::FileDescriptor(fd) => fd.run_command(self, &cmd),
        }
    }

    /// Forks a child and puts it in the previously configured minijail.
    ///
    /// # Safety
    /// `fork` is unsafe because it closes all open FD for this process.  That
    /// could cause a lot of trouble if not handled carefully.  FDs 0, 1, and 2
    /// are overwritten with /dev/null FDs unless they are included in the
    /// inheritable_fds list.
    ///
    /// Also, any Rust objects that own fds may try to close them after the fork. If they belong
    /// to a fd number that was mapped to, the mapped fd will be closed instead.
    ///
    /// This Function may abort in the child on error because a partially
    /// entered jail isn't recoverable.
    ///
    /// Once this is invoked the object is no longer usable, after this call
    /// this minijail object is invalid.
    pub unsafe fn fork(&self, inheritable_fds: Option<&[RawFd]>) -> Result<pid_t> {
        let m: Vec<(RawFd, RawFd)> = inheritable_fds
            .unwrap_or(&[])
            .iter()
            .map(|&a| (a, a))
            .collect();
        self.fork_remap(&m)
    }

    /// Behaves the same as `fork()` except `inheritable_fds` is a list of fd
    /// mappings rather than just a list of fds to preserve.
    ///
    /// # Safety
    /// See `fork`.
    pub unsafe fn fork_remap(&self, inheritable_fds: &[(RawFd, RawFd)]) -> Result<pid_t> {
        if !is_single_threaded().map_err(Error::CheckingMultiThreaded)? {
            // This test will fail during `cargo test` because the test harness always spawns a test
            // thread. We will make an exception for that case because the tests for this module
            // should always be run in a serial fashion using `--test-threads=1`.
            #[cfg(not(test))]
            return Err(Error::ForkingWhileMultiThreaded);
        }

        for (src_fd, dst_fd) in inheritable_fds {
            let ret = minijail_preserve_fd(self.jail, *src_fd, *dst_fd);
            if ret < 0 {
                return Err(Error::PreservingFd(ret));
            }
        }

        let dev_null = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .map_err(Error::OpenDevNull)?;
        // Set stdin, stdout, and stderr to /dev/null unless they are in the inherit list.
        // These will only be closed when this process exits.
        for io_fd in &[libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            if !inheritable_fds.iter().any(|(_, fd)| *fd == *io_fd) {
                let ret = minijail_preserve_fd(self.jail, dev_null.as_raw_fd(), *io_fd);
                if ret < 0 {
                    return Err(Error::PreservingFd(ret));
                }
            }
        }

        minijail_close_open_fds(self.jail);

        let ret = minijail_fork(self.jail);
        if ret < 0 {
            return Err(Error::ForkingMinijail(ret));
        }
        if ret == 0 {
            // Safe because dev_null was remapped.
            dev_null.into_raw_fd();
        }
        Ok(ret as pid_t)
    }

    pub fn wait(&self) -> Result<()> {
        let ret: libc::c_int;
        // This is safe because it does not modify the struct.
        unsafe {
            ret = minijail_wait(self.jail);
        }
        translate_wait_error(ret)
    }

    /// Send a SIGTERM to the child process and wait for its return code.
    pub fn kill(&self) -> Result<()> {
        let ret = unsafe {
            // The kill does not change any internal state.
            minijail_kill(self.jail)
        };
        // minijail_kill waits for the process, so also translate the returned wait error.
        translate_wait_error(ret)
    }
}

impl Drop for Minijail {
    /// Frees the Minijail created in Minijail::new. This will not terminate the
    /// minijailed process.
    fn drop(&mut self) {
        unsafe {
            // Destroys the minijail's memory.  It is safe to do here because all references to
            // this object have been dropped.
            minijail_destroy(self.jail);
        }
    }
}

// Count the number of files in the directory specified by `path`.
fn count_dir_entries<P: AsRef<Path>>(path: P) -> io::Result<usize> {
    Ok(fs::read_dir(path)?.count())
}

// Return true if the current thread is the only thread in the process.
fn is_single_threaded() -> io::Result<bool> {
    match count_dir_entries("/proc/self/task") {
        Ok(1) => Ok(true),
        Ok(_) => Ok(false),
        Err(e) => Err(e),
    }
}

fn to_execve_cstring_array<S: AsRef<str>>(
    slice: &[S],
) -> Result<(Vec<CString>, Vec<*const c_char>)> {
    // Converts each incoming `str` to a `CString`, and then puts each `CString` pointer into a
    // null terminated array, suitable for use as an argv or envp parameter to `execve`.
    let mut vec_cstr = Vec::with_capacity(slice.len());
    let mut vec_cptr = Vec::with_capacity(slice.len() + 1);
    for s in slice {
        let cstr =
            CString::new(s.as_ref()).map_err(|_| Error::StrToCString(s.as_ref().to_owned()))?;

        vec_cstr.push(cstr);
        vec_cptr.push(vec_cstr.last().unwrap().as_ptr());
    }

    vec_cptr.push(null());

    Ok((vec_cstr, vec_cptr))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;

    use libc::{FD_CLOEXEC, F_GETFD, F_SETFD};

    const SHELL: &str = "/bin/sh";
    const EMPTY_STRING_SLICE: &[&str] = &[];

    fn clear_cloexec<A: AsRawFd>(fd_owner: &A) -> StdResult<(), io::Error> {
        let fd = fd_owner.as_raw_fd();
        // Safe because fd is read only.
        let flags = unsafe { libc::fcntl(fd, F_GETFD) };
        if flags == -1 {
            return Err(io::Error::last_os_error());
        }

        let masked_flags = flags & !FD_CLOEXEC;
        // Safe because this has no side effect(s) on the current process.
        if masked_flags != flags && unsafe { libc::fcntl(fd, F_SETFD, masked_flags) } == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[test]
    fn create_and_free() {
        unsafe {
            let j = minijail_new();
            assert_ne!(std::ptr::null_mut(), j);
            minijail_destroy(j);
        }

        let j = Minijail::new().unwrap();
        drop(j);
    }

    #[test]
    // Test that setting a seccomp filter with no-new-privs works as non-root.
    // This is equivalent to minijail0 -n -S <seccomp_policy>
    fn seccomp_no_new_privs() {
        let mut j = Minijail::new().unwrap();
        j.no_new_privs();
        j.parse_seccomp_filters("src/test_filter.policy").unwrap();
        j.use_seccomp_filter();
        j.run("/bin/true", &[], EMPTY_STRING_SLICE).unwrap();
    }

    #[test]
    // Test that open FDs get closed and that FDs in the inherit list are left open.
    fn close_fds() {
        unsafe {
            // Using libc to open/close FDs for testing.
            const FILE_PATH: &[u8] = b"/dev/null\0";
            let j = Minijail::new().unwrap();
            let first = libc::open(FILE_PATH.as_ptr() as *const c_char, libc::O_RDONLY);
            assert!(first >= 0);
            // This appears unused but its function is to be a file descriptor that is closed
            // inside run_remap after the fork. If it is not closed, the script will fail.
            let second = libc::open(FILE_PATH.as_ptr() as *const c_char, libc::O_RDONLY);
            assert!(second >= 0);

            let fds: Vec<(RawFd, RawFd)> = vec![(first, 0), (1, 1), (2, 2)];
            j.run_remap(
                SHELL,
                &fds,
                &[
                    SHELL,
                    "-c",
                    r#"
if [ `ls -l /proc/self/fd/ | grep '/dev/null' | wc -l` != '1' ]; then
  ls -l /proc/self/fd/  # Included to make debugging easier.
  exit 1
fi
"#,
                ],
            )
            .unwrap();
            j.wait().unwrap();
        }
    }

    macro_rules! expect_result {
        ($call:expr, $expected:pat) => {
            let got = $call;
            match got {
                $expected => {}
                _ => {
                    panic!("got {:?} expected {:?}", got, stringify!($expected));
                }
            }
        };
    }

    #[test]
    fn wait_success() {
        let j = Minijail::new().unwrap();
        j.run("/bin/true", &[1, 2], EMPTY_STRING_SLICE).unwrap();
        expect_result!(j.wait(), Ok(()));
    }

    #[test]
    fn wait_killed() {
        let j = Minijail::new().unwrap();
        j.run(
            SHELL,
            &[1, 2],
            &[SHELL, "-c", "kill -9 $$ &\n/usr/bin/sleep 5"],
        )
        .unwrap();
        expect_result!(j.wait(), Err(Error::Killed(9)));
    }

    #[test]
    fn wait_returncode() {
        let j = Minijail::new().unwrap();
        j.run("/bin/false", &[1, 2], EMPTY_STRING_SLICE).unwrap();
        expect_result!(j.wait(), Err(Error::ReturnCode(1)));
    }

    #[test]
    fn wait_noaccess() {
        let j = Minijail::new().unwrap();
        j.run("/dev/null", &[1, 2], EMPTY_STRING_SLICE).unwrap();
        expect_result!(j.wait(), Err(Error::NoAccess));
    }

    #[test]
    fn wait_nocommand() {
        let j = Minijail::new().unwrap();
        j.run("/bin/does not exist", &[1, 2], EMPTY_STRING_SLICE)
            .unwrap();
        // TODO(b/194221986) Fix libminijail so that Error::NoAccess is not sometimes returned.
        assert!(matches!(
            j.wait(),
            Err(Error::NoCommand) | Err(Error::NoAccess)
        ));
    }

    #[test]
    fn runnable_fd_success() {
        let bin_file = File::open("/bin/true").unwrap();
        // On ChromeOS targets /bin/true is actually a script, so drop CLOEXEC to prevent ENOENT.
        clear_cloexec(&bin_file).unwrap();

        let j = Minijail::new().unwrap();
        j.run_fd(&bin_file, &[1, 2], EMPTY_STRING_SLICE).unwrap();
        expect_result!(j.wait(), Ok(()));
    }

    #[test]
    fn kill_success() {
        let j = Minijail::new().unwrap();
        j.run(
            Path::new("/usr/bin/sleep"),
            &[1, 2],
            &["/usr/bin/sleep", "5"],
        )
        .unwrap();
        const EXPECTED_SIGNAL: u8 = libc::SIGTERM as u8;
        expect_result!(j.kill(), Err(Error::Killed(EXPECTED_SIGNAL)));
    }

    #[test]
    #[ignore] // privileged operation.
    fn chroot() {
        let mut j = Minijail::new().unwrap();
        j.enter_chroot(".").unwrap();
        j.run("/bin/true", &[], EMPTY_STRING_SLICE).unwrap();
    }

    #[test]
    #[ignore] // privileged operation.
    fn namespace_vfs() {
        let mut j = Minijail::new().unwrap();
        j.namespace_vfs();
        j.run("/bin/true", &[], EMPTY_STRING_SLICE).unwrap();
    }

    #[test]
    fn run() {
        let j = Minijail::new().unwrap();
        j.run("/bin/true", &[], EMPTY_STRING_SLICE).unwrap();
    }

    #[test]
    fn run_clone() {
        let j = Minijail::new().unwrap();
        let b = j.try_clone().unwrap();
        // Pass the same FDs to both clones and make sure they don't conflict.
        j.run("/bin/true", &[1, 2], EMPTY_STRING_SLICE).unwrap();
        b.run("/bin/true", &[1, 2], EMPTY_STRING_SLICE).unwrap();
    }

    #[test]
    fn run_string_vec() {
        let j = Minijail::new().unwrap();
        let args = vec!["ignored".to_string()];
        j.run(Path::new("/bin/true"), &[], &args).unwrap();
    }
}
