// End-to-end: init, create groups + entries, save, quit, reopen, read back.
// This is the most important regression test — covers init, REPL, mkgroup,
// add, set, save, the dirty-marker, atomic-save backups, and (re-)open.

mod common;

use std::ffi::OsStr;
use std::time::Duration;

const PW: &str = "round-trip-pw-9c";

#[test]
fn write_then_read_back_via_repl() {
    let dir = common::scratch_dir("round-trip");
    let path = common::init_db(&dir, "rt.kdbx", PW);
    assert_eq!(common::mode_of(&path), 0o600);

    // ---- session 1: populate + save -------------------------------------
    {
        let mut s = common::open_repl(&path, PW);

        // mkgroup at root, cd into it, add an entry with username/password/url.
        s.send_line("mkgroup Email");
        s.expect("created group: Email", Duration::from_secs(5));
        // After the mkgroup confirmation, the next prompt rustyline emits
        // should carry the dirty marker.
        s.expect("kpcli:/ *>", Duration::from_secs(5));

        s.send_line("cd Email");
        s.expect("kpcli:/Email *>", Duration::from_secs(5));

        s.send_line("add personal");
        // Each prompt of cmd_add: username, password (rpassword), url, notes.
        s.expect("Username", Duration::from_secs(5));
        s.send_line("alice@example.com");
        s.expect("Password", Duration::from_secs(5));
        s.send_line("hunter2");
        s.expect("URL", Duration::from_secs(5));
        s.send_line("https://example.com");
        s.expect("Notes", Duration::from_secs(5));
        s.send_line("created for round-trip test");
        s.expect("added entry: personal", Duration::from_secs(5));

        // Change a field via `set` to exercise the rest-of-line value parsing.
        s.send_line("set personal username alice-renamed@example.com");
        s.expect("updated: personal.UserName", Duration::from_secs(5));

        s.send_line("save");
        s.expect("saved:", Duration::from_secs(60));
        // If save cleared dirty, the next prompt is the clean form (no `*`).
        // If not, the prompt would have "kpcli:/Email *>" which does *not*
        // contain "kpcli:/Email>" as a substring — so this would time out.
        s.expect("kpcli:/Email>", Duration::from_secs(5));

        s.send_line("quit");
        let code = s.wait();
        assert_eq!(code, 0, "clean quit; log:\n{}", s.log_str());
    }

    // The .bak should exist now (the DB was renamed once mid-save).
    let bak = dir.join("rt.kdbx.bak");
    assert!(bak.exists(), ".bak should exist after the save");
    assert_eq!(common::mode_of(&bak), 0o600, ".bak must be 0600");

    // ---- session 2: reopen + verify -------------------------------------
    {
        let mut s = common::open_repl(&path, PW);

        s.send_line("ls");
        s.expect("Email/", Duration::from_secs(5));

        s.send_line("cd Email");
        s.expect("kpcli:/Email", Duration::from_secs(5));

        s.send_line("show personal");
        s.expect("Title:    personal", Duration::from_secs(5));
        s.expect("Username: alice-renamed@example.com", Duration::from_secs(5));
        s.expect("URL:      https://example.com", Duration::from_secs(5));
        s.expect("Notes:    created for round-trip test", Duration::from_secs(5));
        // Password should be hidden by default.
        s.expect("Password: <hidden", Duration::from_secs(5));

        s.send_line("show personal -f");
        s.expect("Password: hunter2", Duration::from_secs(5));

        // Find by substring across fields, from root.
        s.send_line("cd /");
        s.expect("kpcli:/>", Duration::from_secs(5));
        s.send_line("find example");
        s.expect("/Email/personal", Duration::from_secs(5));

        s.send_line("quit");
        let code = s.wait();
        assert_eq!(code, 0);
    }
}

#[test]
fn quit_with_unsaved_changes_is_refused() {
    let dir = common::scratch_dir("dirty-quit");
    let path = common::init_db(&dir, "dirty.kdbx", PW);

    let mut s = common::open_repl(&path, PW);
    s.send_line("mkgroup Stuff");
    s.expect("created group: Stuff", Duration::from_secs(5));

    s.send_line("quit");
    s.expect("unsaved changes", Duration::from_secs(5));

    // quit! force-exits.
    s.send_line("quit!");
    let code = s.wait();
    assert_eq!(code, 0);

    // .bak must not exist; the group never made it to disk.
    let bak = dir.join("dirty.kdbx.bak");
    assert!(!bak.exists(), "no .bak should be created when changes are discarded");
}

#[test]
fn show_oneshot_reads_existing_entry() {
    // Drive an interactive setup, then verify the one-shot subcommand path.
    let dir = common::scratch_dir("oneshot-show");
    let path = common::init_db(&dir, "os.kdbx", PW);

    // Use the REPL to seed one entry, save, quit.
    {
        let mut s = common::open_repl(&path, PW);
        s.send_line("add api-key");
        s.expect("Username", Duration::from_secs(5));
        s.send_line("svc-account");
        s.expect("Password", Duration::from_secs(5));
        s.send_line("sk-test-abc123");
        s.expect("URL", Duration::from_secs(5));
        s.send_line("");
        s.expect("Notes", Duration::from_secs(5));
        s.send_line("");
        s.expect("added entry: api-key", Duration::from_secs(5));
        s.send_line("save");
        s.expect("saved:", Duration::from_secs(60));
        s.send_line("quit");
        assert_eq!(s.wait(), 0);
    }

    // Now drive `kpcli-rust show <db> /api-key`.
    let mut s = common::Session::spawn(&[
        OsStr::new("show"),
        path.as_os_str(),
        OsStr::new("/api-key"),
    ]);
    s.expect("Master password", Duration::from_secs(5));
    s.send_line(PW);
    s.expect("Title:    api-key", Duration::from_secs(60));
    s.expect("Username: svc-account", Duration::from_secs(5));
    s.expect("Password: <hidden", Duration::from_secs(5));
    assert_eq!(s.wait(), 0);

    // With -f the password is revealed.
    let mut s = common::Session::spawn(&[
        OsStr::new("show"),
        path.as_os_str(),
        OsStr::new("/api-key"),
        OsStr::new("-f"),
    ]);
    s.expect("Master password", Duration::from_secs(5));
    s.send_line(PW);
    s.expect("Password: sk-test-abc123", Duration::from_secs(60));
    assert_eq!(s.wait(), 0);
}
