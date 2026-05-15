// `selftest` and the no-tty sandbox confirmation. Uses run_no_tty because
// selftest takes no input.

mod common;

use std::ffi::OsStr;

#[test]
fn selftest_reports_eaccess() {
    let (code, stdout, _stderr) = common::run_no_tty(&[OsStr::new("selftest")]);
    assert_eq!(code, 0, "selftest exited {code}, stdout was: {stdout}");
    assert!(
        stdout.contains("blocked with EACCES"),
        "selftest stdout did not contain expected substring; got: {stdout}"
    );
}
