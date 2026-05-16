// `purge-history` clears the per-entry value history that imported
// KDBX databases carry. Without it, an imported KeePassXC entry's
// previous-password values stay in the encrypted file even after
// the user rotates with `set entry password`.

mod common;

use std::time::Duration;

use keepass::db::{fields, Database};
use keepass::DatabaseKey;

const PW: &str = "purge-pw-3z";
const T5: Duration = Duration::from_secs(5);
const T60: Duration = Duration::from_secs(60);

#[test]
fn purge_history_clears_imported_entry_history() {
    let dir = common::scratch_dir("purge-history");
    let path = common::init_db(&dir, "ph.kdbx", PW);

    // Inject an entry that already carries a history (as if migrated
    // from KeePassXC). We use the entry's `history` field directly to
    // simulate this.
    {
        let mut f = std::fs::File::open(&path).unwrap();
        let key = DatabaseKey::new().with_password(PW);
        let mut db = Database::open(&mut f, key).unwrap();
        drop(f);

        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected(fields::TITLE, "rotated");
        e.set_protected(fields::PASSWORD, "LEAKED-PASSWORD");
        // Rotate via edit_tracking: this snapshots the current state
        // (LEAKED-PASSWORD) into history, then sets the new value.
        // After the closure, the entry's current PASSWORD is
        // "current-password" and history.entries[0] holds the leaked one.
        e.edit_tracking(|t| {
            t.set_protected(fields::PASSWORD, "current-password");
        });
        let _ = e;
        let _ = root;

        let key = DatabaseKey::new().with_password(PW);
        let mut out = std::fs::File::create(&path).unwrap();
        db.save(&mut out, key).unwrap();
    }

    // Sanity: the leaked password is actually in the encrypted file.
    {
        let mut f = std::fs::File::open(&path).unwrap();
        let key = DatabaseKey::new().with_password(PW);
        let db = Database::open(&mut f, key).unwrap();
        let entry = db
            .iter_all_entries()
            .find(|e| e.get_title() == Some("rotated"))
            .expect("rotated entry must be present");
        let h = entry.history.as_ref().expect("history must be present");
        assert_eq!(h.get_entries().len(), 1, "expected one history entry");
        let prior_pw = h.get_entries()[0]
            .get(fields::PASSWORD)
            .expect("prior version must have a password");
        assert_eq!(prior_pw, "LEAKED-PASSWORD");
    }

    // Drive purge-history through the REPL and save.
    let mut s = common::open_repl(&path, PW);
    s.send_line("purge-history");
    s.expect("cleared history on 1 entries", T5);
    s.send_line("save");
    s.expect("saved:", T60);
    s.send_line("quit");
    assert_eq!(s.wait(), 0);

    // After save: re-open and confirm the history is gone.
    let mut f = std::fs::File::open(&path).unwrap();
    let key = DatabaseKey::new().with_password(PW);
    let db = Database::open(&mut f, key).unwrap();
    let entry = db
        .iter_all_entries()
        .find(|e| e.get_title() == Some("rotated"))
        .expect("rotated entry must persist");
    let history_size = entry.history.as_ref().map_or(0, |h| h.get_entries().len());
    assert_eq!(history_size, 0, "history should be empty after purge");
    // Current password unchanged.
    assert_eq!(entry.get_password(), Some("current-password"));
}

#[test]
fn purge_history_is_noop_when_nothing_to_clear() {
    let dir = common::scratch_dir("purge-noop");
    let path = common::init_db(&dir, "pn.kdbx", PW);
    let mut s = common::open_repl(&path, PW);
    s.send_line("add fresh");
    s.expect("Username", T5);
    s.send_line("");
    s.expect("Password", T5);
    s.send_line("");
    s.expect("URL", T5);
    s.send_line("");
    s.expect("Notes", T5);
    s.send_line("");
    s.expect("added entry: fresh", T5);

    s.send_line("purge-history");
    s.expect("no entry had history to clear", T5);
    s.send_line("quit!");
    assert_eq!(s.wait(), 0);
}
