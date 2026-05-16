// Shared helpers for integration tests. PTY-based driver for kpcli-rust:
// forkpty + execvp, with timeout-bounded reads via libc::select. Kept tiny
// and dependency-light on purpose.
//
// Cargo gives each integration test its own crate, so anything here that a
// given test doesn't use will trigger dead-code warnings — silence them.
#![allow(dead_code)]

use nix::pty::forkpty;
use nix::unistd::ForkResult;
use std::ffi::{CString, OsStr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Absolute path of the kpcli-rust binary built by `cargo test`.
pub fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kpcli-rust"))
}

/// A unique scratch directory under `$CARGO_TARGET_TMPDIR` per-test-per-pid.
/// Created fresh; the previous one (if any) is removed first.
pub fn scratch_dir(name: &str) -> PathBuf {
    let base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("kpcli-rust-tests"));
    let dir = base.join(format!("{}-{}", name, std::process::id()));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).expect("clean scratch");
    }
    std::fs::create_dir_all(&dir).expect("create scratch");
    dir
}

/// Strip ANSI CSI sequences (rustyline emits cursor moves around its prompt).
fn strip_ansi(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == 0x1b && i + 1 < s.len() && s[i + 1] == b'[' {
            i += 2;
            while i < s.len() && !s[i].is_ascii_alphabetic() {
                i += 1;
            }
            if i < s.len() {
                i += 1;
            }
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    out
}

pub struct Session {
    master: OwnedFd,
    pid: nix::unistd::Pid,
    /// All bytes ever read from the pty, unmodified. `log` is derived from
    /// this on demand so we never lose history when ANSI stripping changes
    /// lengths.
    raw_buf: Vec<u8>,
    /// Cumulative ANSI-stripped view of `raw_buf` — useful in assertion
    /// failures.
    pub log: Vec<u8>,
    /// Byte offset into `log` from which the next `expect` should search.
    /// Advances past each successful match so each `expect` only sees
    /// output produced *after* the previous one. This mirrors how
    /// pexpect/Tcl-expect behave and removes the surprise where a stale
    /// substring from an earlier prompt matches immediately.
    search_start: usize,
}

impl Session {
    /// Fork, set up a controlling pty in the child, exec kpcli-rust with the
    /// given args (relative to the binary itself; do not include argv[0]).
    pub fn spawn(args: &[&OsStr]) -> Self {
        // SAFETY: forkpty is async-signal-unsafe but we exec immediately in
        // the child with no allocator/file-descriptor inheritance hazards
        // beyond what nix already handles.
        let result = unsafe { forkpty(None, None) }.expect("forkpty");
        match result.fork_result {
            ForkResult::Parent { child } => Session {
                master: result.master,
                pid: child,
                raw_buf: Vec::new(),
                log: Vec::new(),
                search_start: 0,
            },
            ForkResult::Child => {
                let bin = bin_path();
                let argv0 = CString::new(bin.as_os_str().as_encoded_bytes()).unwrap();
                let mut c_args: Vec<CString> = vec![argv0.clone()];
                for a in args {
                    c_args.push(CString::new(a.as_encoded_bytes()).unwrap());
                }
                let _ = nix::unistd::execv(&argv0, &c_args);
                // execv only returns on failure.
                std::process::exit(127);
            }
        }
    }

    /// Read from the pty until the ANSI-stripped log, *starting from the
    /// position right after the previous `expect`'s match*, contains
    /// `needle`. The search-start position advances past each match.
    pub fn expect(&mut self, needle: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let raw_fd = self.master.as_raw_fd();
        loop {
            // Search only the unread tail of the cumulative log.
            if self.search_start <= self.log.len() {
                if let Some(rel) = find_subsequence(
                    &self.log[self.search_start..],
                    needle.as_bytes(),
                ) {
                    self.search_start += rel + needle.len();
                    return;
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                panic!(
                    "expect timeout looking for {needle:?}\n--- log tail ---\n{}",
                    String::from_utf8_lossy(&self.log)
                );
            }
            // select() with the remaining time as the timeout.
            let mut tv = libc::timeval {
                tv_sec: remaining.as_secs() as libc::time_t,
                tv_usec: remaining.subsec_micros() as libc::suseconds_t,
            };
            let mut readfds: libc::fd_set = unsafe { std::mem::zeroed() };
            unsafe { libc::FD_SET(raw_fd, &mut readfds) };
            let rc = unsafe {
                libc::select(
                    raw_fd + 1,
                    &mut readfds,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut tv,
                )
            };
            if rc < 0 {
                let errno = std::io::Error::last_os_error();
                if errno.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                panic!("select: {errno}");
            }
            if rc == 0 {
                continue; // outer loop will check the deadline
            }
            let mut buf = [0u8; 4096];
            let n = unsafe {
                libc::read(raw_fd, buf.as_mut_ptr() as *mut _, buf.len())
            };
            if n < 0 {
                let errno = std::io::Error::last_os_error();
                // EIO at the master typically means the child closed its side.
                if errno.raw_os_error() == Some(libc::EIO) {
                    panic!(
                        "pty EOF while waiting for {needle:?}\n--- log tail ---\n{}",
                        String::from_utf8_lossy(&self.log)
                    );
                }
                if errno.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                panic!("read: {errno}");
            }
            if n == 0 {
                panic!(
                    "pty closed while waiting for {needle:?}\n--- log tail ---\n{}",
                    String::from_utf8_lossy(&self.log)
                );
            }
            self.raw_buf.extend_from_slice(&buf[..n as usize]);
            // Strip ANSI from the *whole* raw buffer each time — cheap, O(n).
            // Cheaper would be incremental, but ANSI escapes can cross read
            // boundaries; recomputing is the simplest correct option.
            self.log = strip_ansi(&self.raw_buf);
        }
    }

    /// Write `s` followed by a newline.
    pub fn send_line(&mut self, s: &str) {
        let raw_fd = self.master.as_raw_fd();
        let bytes = format!("{s}\n");
        let mut written = 0;
        while written < bytes.len() {
            let n = unsafe {
                libc::write(
                    raw_fd,
                    bytes.as_ptr().add(written) as *const _,
                    bytes.len() - written,
                )
            };
            if n < 0 {
                let errno = std::io::Error::last_os_error();
                if errno.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                panic!("write: {errno}");
            }
            written += n as usize;
        }
    }

    /// Wait for child exit and return its exit status code (or signal as i32).
    pub fn wait(&mut self) -> i32 {
        // Drain anything still sitting in the pty buffer first.
        let raw_fd = self.master.as_raw_fd();
        loop {
            let mut buf = [0u8; 4096];
            let mut tv = libc::timeval { tv_sec: 0, tv_usec: 200_000 };
            let mut readfds: libc::fd_set = unsafe { std::mem::zeroed() };
            unsafe { libc::FD_SET(raw_fd, &mut readfds) };
            let rc = unsafe {
                libc::select(
                    raw_fd + 1,
                    &mut readfds,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut tv,
                )
            };
            if rc <= 0 {
                break;
            }
            let n = unsafe { libc::read(raw_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n <= 0 {
                break;
            }
            self.raw_buf.extend_from_slice(&buf[..n as usize]);
            self.log = strip_ansi(&self.raw_buf);
        }

        let mut status: libc::c_int = 0;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let rc = unsafe {
                libc::waitpid(self.pid.as_raw(), &mut status, libc::WNOHANG)
            };
            if rc == self.pid.as_raw() {
                if libc::WIFEXITED(status) {
                    return libc::WEXITSTATUS(status);
                }
                if libc::WIFSIGNALED(status) {
                    return 128 + libc::WTERMSIG(status);
                }
                return -1;
            }
            if Instant::now() > deadline {
                // Give up and signal-kill.
                unsafe { libc::kill(self.pid.as_raw(), libc::SIGKILL) };
                let _ = unsafe { libc::waitpid(self.pid.as_raw(), &mut status, 0) };
                return -1;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Get the current cleaned log as a string (for ad-hoc assertions).
    pub fn log_str(&self) -> String {
        String::from_utf8_lossy(&self.log).into_owned()
    }

    /// Reset the cumulative log so subsequent `expect`s and `log_str()`
    /// only see output produced after this point. Useful for asserting on
    /// "the next prompt" after a command's confirmation has been seen.
    pub fn clear_log(&mut self) {
        self.raw_buf.clear();
        self.log.clear();
        self.search_start = 0;
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Best effort: SIGKILL if the child is still around.
        unsafe {
            libc::kill(self.pid.as_raw(), libc::SIGKILL);
            let mut status: libc::c_int = 0;
            libc::waitpid(self.pid.as_raw(), &mut status, libc::WNOHANG);
        }
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// Convenience: read the mode bits (Unix) of a path.
pub fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .expect("stat")
        .permissions()
        .mode()
        & 0o777
}

/// Convenience: invoke kpcli-rust as a normal child process (no PTY) and
/// return (exit code, stdout, stderr). Use this only for commands that
/// don't require a TTY (e.g. `selftest`).
pub fn run_no_tty(args: &[&OsStr]) -> (i32, String, String) {
    use std::process::Command;
    let out = Command::new(bin_path())
        .args(args)
        .output()
        .expect("spawn");
    let code = out.status.code().unwrap_or(-1);
    (
        code,
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Convenience: drive a full `init` flow, returning the path of the new DB.
pub fn init_db(dir: &Path, name: &str, password: &str) -> PathBuf {
    let path = dir.join(name);
    let mut s = Session::spawn(&[OsStr::new("init"), path.as_os_str()]);
    s.expect("New master password", Duration::from_secs(5));
    s.send_line(password);
    s.expect("Confirm master password", Duration::from_secs(5));
    s.send_line(password);
    s.expect("created:", Duration::from_secs(120));
    let code = s.wait();
    assert_eq!(code, 0, "init exited {code}; log:\n{}", s.log_str());
    path
}

/// Convenience: drive an `open` (REPL) up to the first prompt.
pub fn open_repl(path: &Path, password: &str) -> Session {
    let mut s = Session::spawn(&[path.as_os_str()]);
    s.expect("Master password for", Duration::from_secs(5));
    s.send_line(password);
    s.expect("kpcli:", Duration::from_secs(120));
    s
}

