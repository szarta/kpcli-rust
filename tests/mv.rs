// `mv` command: rename-in-place, move-into-group, move-and-rename, and
// collision/error cases.

mod common;

use std::time::Duration;

const PW: &str = "mv-test-77";
const T5: Duration = Duration::from_secs(5);
const T60: Duration = Duration::from_secs(60);

#[test]
fn mv_supports_rename_move_and_collisions() {
    let dir = common::scratch_dir("mv");
    let path = common::init_db(&dir, "mv.kdbx", PW);
    let mut s = common::open_repl(&path, PW);

    // Build: /Email/work, /Personal (empty)
    s.send_line("mkgroup Email");
    s.expect("created group: Email", T5);
    s.send_line("mkgroup Personal");
    s.expect("created group: Personal", T5);

    s.send_line("cd Email");
    s.expect("kpcli:/Email *>", T5);

    s.send_line("add work");
    s.expect("Username", T5);
    s.send_line("");
    s.expect("Password", T5);
    s.send_line("");
    s.expect("URL", T5);
    s.send_line("");
    s.expect("Notes", T5);
    s.send_line("");
    s.expect("added entry: work", T5);

    // --- rename in place: bare destination ----------------------------
    s.send_line("mv work job");
    s.expect("moved: work -> /Email/job", T5);
    s.send_line("ls");
    s.expect("job", T5);

    // --- move into an existing group: trailing slash ------------------
    s.send_line("mv job /Personal/");
    s.expect("moved: job -> /Personal/job", T5);

    s.send_line("cd /Personal");
    s.expect("kpcli:/Personal *>", T5);
    s.send_line("ls");
    s.expect("job", T5);

    // --- move + rename: explicit destination path ---------------------
    s.send_line("mv job /Email/renamed-job");
    s.expect("moved: job -> /Email/renamed-job", T5);

    s.send_line("cd /Email");
    s.expect("kpcli:/Email *>", T5);
    s.send_line("ls");
    s.expect("renamed-job", T5);

    // --- collision refused --------------------------------------------
    s.send_line("add other");
    s.expect("Username", T5);
    s.send_line("");
    s.expect("Password", T5);
    s.send_line("");
    s.expect("URL", T5);
    s.send_line("");
    s.expect("Notes", T5);
    s.send_line("");
    s.expect("added entry: other", T5);

    s.send_line("mv renamed-job other");
    s.expect("already exists", T5);

    // --- self-move refused --------------------------------------------
    s.send_line("mv renamed-job renamed-job");
    s.expect("source and destination are the same", T5);

    // --- bad destination forms ----------------------------------------
    s.send_line("mv renamed-job a/");
    s.expect("no such group", T5);

    // --- group rename + move ------------------------------------------
    s.send_line("cd /");
    s.expect("kpcli:/ *>", T5);

    s.send_line("mkgroup Junk");
    s.expect("created group: Junk", T5);

    s.send_line("mv Junk Trash");
    s.expect("moved: Junk -> /Trash", T5);

    s.send_line("mv Trash /Personal/");
    s.expect("moved: Trash -> /Personal/Trash", T5);

    s.send_line("cd /Personal");
    s.expect("kpcli:/Personal *>", T5);
    s.send_line("ls");
    s.expect("Trash/", T5);

    // --- save, reopen, verify persistence -----------------------------
    s.send_line("save");
    s.expect("saved:", T60);
    s.send_line("quit");
    assert_eq!(s.wait(), 0);

    let mut s = common::open_repl(&path, PW);
    s.send_line("cd /Personal");
    s.expect("kpcli:/Personal>", T5);
    s.send_line("ls");
    s.expect("Trash/", T5);
    s.send_line("cd /Email");
    s.expect("kpcli:/Email", T5);
    s.send_line("ls");
    s.expect("renamed-job", T5);
    s.send_line("quit");
    assert_eq!(s.wait(), 0);
}
