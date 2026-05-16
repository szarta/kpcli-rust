// The enumerated wrong-password / missing-keyfile / corruption message added
// in task #2.

mod common;

use std::ffi::OsStr;
use std::time::Duration;

#[test]
fn wrong_password_produces_enumerated_message() {
    let dir = common::scratch_dir("wrong-pw");
    let path = common::init_db(&dir, "wp.kdbx", "correct-pw");

    let mut s = common::Session::spawn(&[OsStr::new("open"), path.as_os_str()]);
    s.expect("Master password", Duration::from_secs(5));
    s.send_line("INCORRECT");
    s.expect("could not decrypt", Duration::from_secs(60));
    let log = s.log_str();
    assert!(
        log.contains("the master password is wrong"),
        "missing wrong-pw bullet:\n{log}"
    );
    assert!(
        log.contains("keyfile") && log.contains("does not support keyfiles"),
        "missing keyfile bullet:\n{log}"
    );
    assert!(log.contains("corrupted"), "missing corruption bullet:\n{log}");

    let code = s.wait();
    assert_ne!(code, 0, "open with wrong pw should exit non-zero");
}
