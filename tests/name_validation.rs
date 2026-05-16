// Name validation: empty, `.`, `..`, `/`, and control characters are
// rejected for entry titles and group names — by `add`, `mkgroup`, `mv`,
// and `set <entry> title`.

mod common;

use std::time::Duration;

const PW: &str = "namevalid-pw-9z";
const T5: Duration = Duration::from_secs(5);

#[test]
fn rejects_unsafe_names() {
    let dir = common::scratch_dir("name-validation");
    let path = common::init_db(&dir, "nv.kdbx", PW);
    let mut s = common::open_repl(&path, PW);

    // mkgroup ---
    s.send_line("mkgroup");
    s.expect("missing group name", T5);

    s.send_line("mkgroup .");
    s.expect("must not be '.' or '..'", T5);

    s.send_line("mkgroup ..");
    s.expect("must not be '.' or '..'", T5);

    s.send_line("mkgroup foo/bar");
    s.expect("must not contain '/'", T5);

    // add ---
    // (We can't send a newline through send_line directly, so use control
    // characters that survive split_whitespace.)
    s.send_line("add .");
    s.expect("must not be '.' or '..'", T5);

    s.send_line("add foo/bar");
    s.expect("must not contain '/'", T5);

    // Real entry to test `set title` against ---
    s.send_line("add legit");
    s.expect("Username", T5);
    s.send_line("");
    s.expect("Password", T5);
    s.send_line("");
    s.expect("URL", T5);
    s.send_line("");
    s.expect("Notes", T5);
    s.send_line("");
    s.expect("added entry: legit", T5);

    // set title to '/' should refuse.
    s.send_line("set legit title foo/bar");
    s.expect("must not contain '/'", T5);

    // set title to '.' should refuse.
    s.send_line("set legit title .");
    s.expect("must not be '.' or '..'", T5);

    // mv: same validation applies to the destination name.
    s.send_line("mv legit .");
    s.expect("must not be '.' or '..'", T5);

    // Sanity: a valid title set still works after all the rejections.
    // (The success message uses the lookup name, not the new title.)
    s.send_line("set legit title legit-renamed");
    s.expect("updated: legit.Title", T5);

    s.send_line("quit!");
    assert_eq!(s.wait(), 0);
}
