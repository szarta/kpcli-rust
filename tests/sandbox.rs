// `selftest` and the no-tty sandbox confirmation. Uses run_no_tty because
// selftest takes no input.

mod common;

use std::ffi::OsStr;

#[test]
fn selftest_reports_eaccess() {
    let (code, stdout, _stderr) = common::run_no_tty(&[OsStr::new("selftest")]);
    assert_eq!(code, 0, "selftest exited {code}, stdout was: {stdout}");
    // The selftest probes both socket() and io_uring_setup; its success
    // message names both.
    assert!(
        stdout.contains("socket(AF_INET)") && stdout.contains("io_uring_setup"),
        "selftest stdout did not name both probed syscalls; got: {stdout}"
    );
    assert!(
        stdout.contains("blocked"),
        "selftest stdout missing 'blocked'; got: {stdout}"
    );
}
