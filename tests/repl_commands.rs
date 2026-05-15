// Broad command coverage. Bundled into one function so we pay the Argon2id
// derivation cost once. Order matters: each section sets up state for the
// next.

mod common;

use std::time::Duration;

const PW: &str = "repl-cov-99";
const T5: Duration = Duration::from_secs(5);
const T60: Duration = Duration::from_secs(60);

#[test]
fn repl_command_coverage() {
    let dir = common::scratch_dir("repl-cov");
    let path = common::init_db(&dir, "cov.kdbx", PW);

    let mut s = common::open_repl(&path, PW);

    // ---- help / pwd / ls (empty) ---------------------------------------
    s.send_line("help");
    s.expect("commands:", T5);
    s.expect("mkgroup", T5);
    s.expect("quit", T5);

    s.send_line("pwd");
    s.expect("/", T5);

    s.send_line("ls");
    s.expect("(empty)", T5);

    // ---- mkgroup (and duplicate refusal) -------------------------------
    s.send_line("mkgroup Email");
    s.expect("created group: Email", T5);

    s.send_line("mkgroup Email");
    s.expect("group already exists", T5);

    s.send_line("mkgroup Servers");
    s.expect("created group: Servers", T5);
    // Consume the prompt that follows so the next "kpcli:" expect won't
    // match a stale prompt instead of waiting for fresh output.
    s.expect("kpcli:/ *>", T5);

    // ---- ls / cd (root, relative, absolute, parent, non-existent) ------
    // `keepass` stores subgroups in a HashSet — iteration order is
    // non-deterministic — so check that both names appear in the next ls
    // output without asserting an order.
    s.send_line("ls");
    s.expect("kpcli:/ *>", T5);
    let log = s.log_str();
    assert!(log.contains("Email/"), "ls missing Email/:\n{log}");
    assert!(log.contains("Servers/"), "ls missing Servers/:\n{log}");

    s.send_line("cd Email");
    s.expect("kpcli:/Email *>", T5);

    s.send_line("cd ..");
    s.expect("kpcli:/ *>", T5);

    s.send_line("cd /Servers");
    s.expect("kpcli:/Servers *>", T5);

    s.send_line("cd /");
    s.expect("kpcli:/ *>", T5);

    s.send_line("cd nope");
    s.expect("no such group", T5);

    // ---- add / set fields ----------------------------------------------
    s.send_line("cd Email");
    s.expect("kpcli:/Email *>", T5);

    s.send_line("add work");
    s.expect("Username", T5);
    s.send_line("user@work.example");
    s.expect("Password", T5);
    s.send_line("initialpw");
    s.expect("URL", T5);
    s.send_line("https://work.example");
    s.expect("Notes", T5);
    s.send_line("Initial notes");
    s.expect("added entry: work", T5);

    // Renaming via `set <entry> title` changes the entry name; subsequent
    // commands must reference the entry by its new title. This is the
    // documented behavior — title is the lookup key.
    s.send_line("set work title work-renamed");
    s.expect("updated: work.Title", T5);

    s.send_line("set work-renamed url https://mail.work.example/inbox?x=1");
    s.expect("updated: work-renamed.URL", T5);

    s.send_line("set work-renamed notes a longer note   with   internal   spaces");
    s.expect("updated: work-renamed.Notes", T5);

    // Inline password is refused; password must be re-prompted.
    s.send_line("set work-renamed password should-not-set-inline");
    s.expect("refusing to take a password on the command line", T5);

    // Proper password re-set via prompt + confirm.
    s.send_line("set work-renamed password");
    s.expect("New password:", T5);
    s.send_line("rotated-pw");
    s.expect("Confirm:", T5);
    s.send_line("rotated-pw");
    s.expect("updated: work-renamed.Password", T5);

    // Mismatched confirm is rejected.
    s.send_line("set work-renamed password");
    s.expect("New password:", T5);
    s.send_line("one");
    s.expect("Confirm:", T5);
    s.send_line("two");
    s.expect("passwords do not match", T5);

    // ---- find ----------------------------------------------------------
    s.send_line("find work.example");
    s.expect("/Email/work-renamed", T5);

    s.send_line("find no-such-thing-anywhere");
    s.expect("(no matches)", T5);

    // ---- show: title was renamed above; password is hidden by default
    //       and reveals with -f.
    s.send_line("show work-renamed");
    s.expect("Title:    work-renamed", T5);
    s.expect("Username: user@work.example", T5);
    s.expect("URL:      https://mail.work.example/inbox?x=1", T5);
    s.expect("Notes:    a longer note   with   internal   spaces", T5);
    s.expect("Password: <hidden", T5);

    s.send_line("show work-renamed -f");
    s.expect("Password: rotated-pw", T5);

    // ---- rm: entry, group (non-empty refused without -r), group with -r
    s.send_line("cd /");
    s.expect("kpcli:/ *>", T5);

    // Create a group with a child entry, prove rm refuses without -r.
    s.send_line("mkgroup Throwaway");
    s.expect("created group: Throwaway", T5);
    s.send_line("cd Throwaway");
    s.expect("kpcli:/Throwaway *>", T5);
    s.send_line("add child");
    s.expect("Username", T5);
    s.send_line("");
    s.expect("Password", T5);
    s.send_line("");
    s.expect("URL", T5);
    s.send_line("");
    s.expect("Notes", T5);
    s.send_line("");
    s.expect("added entry: child", T5);

    s.send_line("cd ..");
    s.expect("kpcli:/ *>", T5);

    s.send_line("rm Throwaway");
    s.expect("not empty", T5);

    s.send_line("rm -r Throwaway");
    s.expect("removed group: Throwaway", T5);

    // Remove the (renamed) work entry.
    s.send_line("cd Email");
    s.expect("kpcli:/Email *>", T5);
    s.send_line("rm work-renamed");
    s.expect("removed entry: work-renamed", T5);

    // Empty group can be rm'd without -r.
    s.send_line("cd ..");
    s.expect("kpcli:/ *>", T5);
    s.send_line("rm Email");
    s.expect("removed group: Email", T5);

    // ---- save then verify .bak --------------------------------------
    s.send_line("save");
    s.expect("saved:", T60);
    // After save, dirty is cleared — the next prompt is the clean form.
    s.expect("kpcli:/>", T5);
    assert!(dir.join("cov.kdbx.bak").exists(), ".bak should exist after save");
    assert_eq!(common::mode_of(&dir.join("cov.kdbx.bak")), 0o600);

    s.send_line("quit");
    let code = s.wait();
    assert_eq!(code, 0, "clean quit; log:\n{}", s.log_str());
}
