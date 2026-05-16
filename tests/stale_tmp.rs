// Crash-safety: if a previous save left a stale .tmp behind, the next save
// must refuse rather than clobber it.

mod common;

use std::time::Duration;

#[test]
fn save_refuses_with_stale_tmp() {
    let dir = common::scratch_dir("stale-tmp");
    let path = common::init_db(&dir, "st.kdbx", "stale-pw");

    // Pre-create a stale .tmp adjacent to the DB.
    let tmp = dir.join("st.kdbx.tmp");
    std::fs::write(&tmp, b"leftover from a previous interrupted save").unwrap();

    let mut s = common::open_repl(&path, "stale-pw");
    s.send_line("mkgroup Things");
    s.expect("created group: Things", Duration::from_secs(5));
    s.send_line("save");
    s.expect("stale", Duration::from_secs(60));
    let log = s.log_str();
    assert!(
        log.contains("inspect and remove"),
        "save error should suggest inspecting the .tmp; got:\n{log}"
    );

    // Cleanup: force-quit (the change is unsaved by design).
    s.send_line("quit!");
    let code = s.wait();
    assert_eq!(code, 0);

    // Stale .tmp must still be there — save shouldn't have touched it.
    assert!(tmp.exists(), ".tmp should be untouched");
}
