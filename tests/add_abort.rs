// Aborting mid-`add` with a `.` on any prompt must NOT create the entry.

mod common;

use std::time::Duration;

const PW: &str = "add-abort-pw-3z";
const T5: Duration = Duration::from_secs(5);
const T60: Duration = Duration::from_secs(60);

#[test]
fn dot_aborts_add_at_each_prompt() {
    let dir = common::scratch_dir("add-abort");
    let path = common::init_db(&dir, "aa.kdbx", PW);

    let mut s = common::open_repl(&path, PW);

    // Abort at the very first (username) prompt.
    s.send_line("add target-1");
    s.expect("Username", T5);
    s.send_line(".");
    s.expect("(add aborted; no entry created)", T5);

    // Abort at the password prompt.
    s.send_line("add target-2");
    s.expect("Username", T5);
    s.send_line("u");
    s.expect("Password", T5);
    s.send_line(".");
    s.expect("(add aborted; no entry created)", T5);

    // Abort at the URL prompt.
    s.send_line("add target-3");
    s.expect("Username", T5);
    s.send_line("u");
    s.expect("Password", T5);
    s.send_line("p");
    s.expect("URL", T5);
    s.send_line(".");
    s.expect("(add aborted; no entry created)", T5);

    // Abort at the notes prompt.
    s.send_line("add target-4");
    s.expect("Username", T5);
    s.send_line("u");
    s.expect("Password", T5);
    s.send_line("p");
    s.expect("URL", T5);
    s.send_line("");
    s.expect("Notes", T5);
    s.send_line(".");
    s.expect("(add aborted; no entry created)", T5);

    // The DB should still be empty — none of the attempts created an entry.
    s.send_line("ls");
    s.expect("(empty)", T5);

    // Sanity: a non-aborted add still works.
    s.send_line("add survives");
    s.expect("Username", T5);
    s.send_line("");
    s.expect("Password", T5);
    s.send_line("");
    s.expect("URL", T5);
    s.send_line("");
    s.expect("Notes", T5);
    s.send_line("");
    s.expect("added entry: survives", T5);

    // And ".' is a valid password if the user really wants — well, no, it
    // aborts. That's the documented trade-off.

    s.send_line("save");
    s.expect("saved:", T60);
    s.send_line("quit");
    assert_eq!(s.wait(), 0);
}
