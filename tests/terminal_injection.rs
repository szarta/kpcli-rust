// A migrated / hostile KDBX must not be able to use ANSI / OSC sequences
// in field values or names to manipulate the terminal when displayed
// via show / ls / find. Specifically OSC 52 (clipboard write) would
// defeat the "no clipboard linkage" stance entirely.

mod common;

use std::ffi::OsStr;
use std::time::Duration;

use keepass::db::{fields, Database, Value};
use keepass::DatabaseKey;

const PW: &str = "term-inj-pw-77";
const T5: Duration = Duration::from_secs(5);
const T60: Duration = Duration::from_secs(60);

#[test]
fn show_escapes_ansi_and_osc_in_db_content() {
    let dir = common::scratch_dir("term-injection");
    let path = common::init_db(&dir, "ti.kdbx", PW);

    // Inject a hostile entry: name + values carrying control characters
    // including an OSC 52 clipboard-write sequence and a CSI cursor-move.
    {
        let mut f = std::fs::File::open(&path).unwrap();
        let key = DatabaseKey::new().with_password(PW);
        let mut db = Database::open(&mut f, key).unwrap();
        drop(f);

        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected(fields::TITLE, "hostile");
        e.set_unprotected(
            fields::USERNAME,
            "alice\x1b[2K\rPassword: SPOOFED",
        );
        // OSC 52 clipboard write — the canary the agent flagged.
        e.set_unprotected(
            fields::NOTES,
            "see clipboard \x1b]52;c;QUtJOiBoYXJkLWNvZGVk\x07 trick",
        );
        e.set("Custom\x1b]0;hijack\x07", Value::unprotected("safe-key"));
        let _ = e;
        let _ = root;

        let key = DatabaseKey::new().with_password(PW);
        let mut out = std::fs::File::create(&path).unwrap();
        db.save(&mut out, key).unwrap();
    }

    let mut s = common::Session::spawn(&[
        OsStr::new("show"),
        path.as_os_str(),
        OsStr::new("/hostile"),
        OsStr::new("-f"),
    ]);
    s.expect("Master password", T5);
    s.send_line(PW);
    s.expect("Title:    hostile", T60);
    // No raw escape bytes should appear in stdout — they should be
    // rendered as \xHH. The harness's ANSI stripper would silently
    // remove them; assert on the escaped form instead.
    s.expect("\\x1b", T5);

    let log = s.log_str();
    // No literal OSC end (BEL byte, 0x07) should reach the terminal.
    assert!(
        !log.contains('\u{0007}'),
        "BEL byte must not reach the terminal verbatim"
    );
    // The CSI 2K (clear line) sequence should be escaped.
    assert!(
        log.contains("\\x1b[2K") || log.contains("\\x1b") && log.contains("[2K"),
        "expected CSI 2K to be rendered as \\x1b[2K; log:\n{log}"
    );

    assert_eq!(s.wait(), 0);
}
