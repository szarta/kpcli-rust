// If another writer has replaced the database file between our open and
// our save, `save` must refuse rather than silently clobbering. Catches
// the common "two REPLs open on the same DB" foot-gun without holding an
// OS-level flock (which would need a sidecar lock file or race with our
// atomic-rename save sequence).

mod common;

use std::time::Duration;

use keepass::db::Database;
use keepass::DatabaseKey;

const PW: &str = "concurrent-77";
const T5: Duration = Duration::from_secs(5);

#[test]
fn save_refuses_when_db_replaced_by_another_writer() {
    let dir = common::scratch_dir("concurrent");
    let path = common::init_db(&dir, "c.kdbx", PW);

    let mut s = common::open_repl(&path, PW);
    s.send_line("mkgroup MineFirst");
    s.expect("created group: MineFirst", T5);

    // Simulate the "other process saved" case: open the DB ourselves,
    // make a different change, and write back via the keepass crate's
    // save (which goes through a different path than save_atomic but
    // ends up replacing <path> with a new inode).
    {
        let mut f = std::fs::File::open(&path).unwrap();
        let key = DatabaseKey::new().with_password(PW);
        let mut db = Database::open(&mut f, key).unwrap();
        drop(f);

        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected("Title", "from-other-process");
        drop(e);
        drop(root);

        // Match what kpcli-rust does: write to a tmp, rename into place.
        // (Not necessary for the inode-change semantics, but keeps the
        // moving parts realistic.)
        let tmp = dir.join("c.kdbx.other-tmp");
        let mut out = std::fs::File::create(&tmp).unwrap();
        let key = DatabaseKey::new().with_password(PW);
        db.save(&mut out, key).unwrap();
        drop(out);
        std::fs::rename(&tmp, &path).unwrap();
    }

    // Now try saving from the REPL — should refuse.
    s.send_line("save");
    s.expect("modified by another process", T5);

    // The REPL's in-memory state is still dirty; quit! to discard.
    s.send_line("quit!");
    let code = s.wait();
    assert_eq!(code, 0);

    // Reopen and confirm the OTHER process's change made it to disk and
    // ours did NOT (since the REPL refused to save).
    let mut f = std::fs::File::open(&path).unwrap();
    let key = DatabaseKey::new().with_password(PW);
    let db = Database::open(&mut f, key).unwrap();
    let titles: Vec<String> = db
        .iter_all_entries()
        .map(|e| e.get_title().unwrap_or("").to_string())
        .collect();
    assert!(
        titles.iter().any(|t| t == "from-other-process"),
        "other process's entry must be persisted; titles={titles:?}"
    );
    // Our REPL's MineFirst group should NOT exist (we refused to save).
    let group_names: Vec<String> = db
        .root()
        .groups()
        .map(|g| g.name.clone())
        .collect();
    assert!(
        !group_names.iter().any(|n| n == "MineFirst"),
        "REPL's discarded change leaked into the file; groups={group_names:?}"
    );
}
