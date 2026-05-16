// `show` must surface custom (non-canonical) string fields — KDBX entries
// imported from KeePassXC or other clients routinely carry TOTP secrets,
// recovery codes, etc., as custom string fields. Protected custom fields
// are hidden behind `-f` just like the password.

mod common;

use std::ffi::OsStr;
use std::time::Duration;

use keepass::db::{fields, Database, Value};
use keepass::DatabaseKey;

const PW: &str = "custom-fields-77";
const T5: Duration = Duration::from_secs(5);
const T60: Duration = Duration::from_secs(60);

#[test]
fn show_lists_custom_string_fields() {
    let dir = common::scratch_dir("custom-fields");
    let path = common::init_db(&dir, "cf.kdbx", PW);

    // Inject an entry with both canonical and custom fields directly via
    // the keepass crate (no REPL path to add custom fields today).
    {
        let mut f = std::fs::File::open(&path).unwrap();
        let key = DatabaseKey::new().with_password(PW);
        let mut db = Database::open(&mut f, key).unwrap();
        drop(f);

        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(fields::TITLE, "imported");
        entry.set_unprotected(fields::USERNAME, "carol");
        entry.set_protected(fields::PASSWORD, "real-password");
        entry.set_unprotected("Recovery Codes", "11111-22222-33333");
        // Custom *protected* field — TOTP secret, treated like the password.
        entry.set("TOTP Seed", Value::protected("JBSWY3DPEHPK3PXP"));
        let _ = entry;
        let _ = root;

        // Save with the same atomic semantics by going through the REPL? No,
        // the test only needs persistence — use the keepass save API.
        let key = DatabaseKey::new().with_password(PW);
        let mut out = std::fs::File::create(&path).unwrap();
        db.save(&mut out, key).unwrap();
        // The test only cares that the entry is on disk and we can read
        // it via kpcli-rust afterwards. File mode test is separate.
    }

    // Show without -f: canonical fields visible, password hidden, custom
    // protected field hidden, custom unprotected field visible.
    let mut s = common::Session::spawn(&[
        OsStr::new("show"),
        path.as_os_str(),
        OsStr::new("/imported"),
    ]);
    s.expect("Master password", T5);
    s.send_line(PW);
    s.expect("Title:    imported", T60);
    s.expect("Username: carol", T5);
    s.expect("Password: <hidden", T5);
    s.expect("Recovery Codes: 11111-22222-33333", T5);
    s.expect("TOTP Seed: <hidden", T5);
    assert_eq!(s.wait(), 0);

    // Show with -f: protected custom field is revealed.
    let mut s = common::Session::spawn(&[
        OsStr::new("show"),
        path.as_os_str(),
        OsStr::new("/imported"),
        OsStr::new("-f"),
    ]);
    s.expect("Master password", T5);
    s.send_line(PW);
    s.expect("Password: real-password", T60);
    s.expect("Recovery Codes: 11111-22222-33333", T5);
    s.expect("TOTP Seed: JBSWY3DPEHPK3PXP", T5);
    assert_eq!(s.wait(), 0);
}
