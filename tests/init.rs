// Verify `init` creates a 0600 KDBX4 file and refuses to overwrite.

mod common;

use std::ffi::OsStr;
use std::time::Duration;

#[test]
fn init_creates_0600_db() {
    let dir = common::scratch_dir("init-0600");
    let path = common::init_db(&dir, "fresh.kdbx", "test-pw-123");
    assert!(path.exists());
    let mode = common::mode_of(&path);
    assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
}

#[test]
fn init_refuses_to_overwrite_existing_file() {
    let dir = common::scratch_dir("init-no-clobber");
    let path = dir.join("present.kdbx");
    std::fs::write(&path, b"already here").unwrap();

    let mut s = common::Session::spawn(&[OsStr::new("init"), path.as_os_str()]);
    s.expect("refusing to overwrite", Duration::from_secs(5));
    let code = s.wait();
    assert_ne!(code, 0, "init should fail on existing file");

    // File untouched.
    assert_eq!(std::fs::read(&path).unwrap(), b"already here");
}

#[test]
fn init_refuses_mismatched_confirm() {
    let dir = common::scratch_dir("init-mismatch");
    let path = dir.join("nope.kdbx");

    let mut s = common::Session::spawn(&[OsStr::new("init"), path.as_os_str()]);
    s.expect("New master password", Duration::from_secs(5));
    s.send_line("first");
    s.expect("Confirm master password", Duration::from_secs(5));
    s.send_line("second");
    s.expect("do not match", Duration::from_secs(5));
    let code = s.wait();
    assert_ne!(code, 0);
    assert!(!path.exists(), "DB should not have been created");
}
