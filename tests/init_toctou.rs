// If a file materializes at the destination path between init's
// pre-check and the rename, save_atomic must refuse to silently move
// it to <db>.bak. Tests the (expected_fs_id == None) branch of the
// concurrent-save guard.

mod common;

use std::ffi::OsStr;
use std::time::Duration;

#[test]
fn init_refuses_when_path_materializes_during_derivation() {
    let dir = common::scratch_dir("init-toctou");
    let path = dir.join("race.kdbx");
    let pre_existing_marker = b"foreign file placed mid-init";

    // Race simulation: spawn `init`, wait for the password prompts to
    // finish (so the Argon2id derivation has started), then place a file
    // at the target path. The init's save_atomic guard must catch this.
    let mut s = common::Session::spawn(&[OsStr::new("init"), path.as_os_str()]);
    s.expect("New master password", Duration::from_secs(5));
    s.send_line("toctou-pw");
    s.expect("Confirm master password", Duration::from_secs(5));
    s.send_line("toctou-pw");
    // Now Argon2id derivation runs — there's a multi-second window.
    // Inject the foreign file.
    std::fs::write(&path, pre_existing_marker).unwrap();

    // save_atomic has two refusal sites — one at the start (before
    // Argon2) and one after the derivation but before rename-to-bak.
    // Both error messages share "during init"; we accept either.
    s.expect("during init", Duration::from_secs(120));
    let code = s.wait();
    assert_ne!(code, 0, "init should fail when path materialized mid-run");

    // The injected file must still be there, untouched — we did not
    // rename it to a backup.
    let bak = dir.join("race.kdbx.bak");
    assert!(!bak.exists(), "no .bak should have been produced");
    let now_on_disk = std::fs::read(&path).expect("foreign file must still be there");
    assert_eq!(
        now_on_disk, pre_existing_marker,
        "foreign file should be untouched"
    );
}

#[test]
fn init_refuses_when_path_materializes_late_during_derivation() {
    // Same as the above test but deliberately waits past save_atomic's
    // first fs_id check, so the file appears during the Argon2 derivation
    // and the *late* check (after derivation) is the one that fires.
    let dir = common::scratch_dir("init-toctou-late");
    let path = dir.join("late.kdbx");

    let mut s = common::Session::spawn(&[OsStr::new("init"), path.as_os_str()]);
    s.expect("New master password", Duration::from_secs(5));
    s.send_line("late-pw");
    s.expect("Confirm master password", Duration::from_secs(5));
    s.send_line("late-pw");
    // Sleep long enough that save_atomic has cleared the early fs_id
    // check and is well into the Argon2id derivation when the foreign
    // file appears.
    std::thread::sleep(Duration::from_millis(2_000));
    std::fs::write(&path, b"late-arrival").unwrap();

    s.expect("during init", Duration::from_secs(120));
    let code = s.wait();
    assert_ne!(code, 0);

    let bak = dir.join("late.kdbx.bak");
    assert!(!bak.exists());
    assert_eq!(std::fs::read(&path).unwrap(), b"late-arrival");
}
