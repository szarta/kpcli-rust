// Build a small KDBX4 database for end-to-end testing of kpcli-rust.
// Run with:  cargo run --example make_fixture -- /tmp/test.kdbx
// (the password is prompted on /dev/tty; never pass it on the command line)

use keepass::{
    db::{fields, Database},
    DatabaseKey,
};
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path: String = args.next().expect("usage: make_fixture <path>");
    let password = rpassword::prompt_password("fixture password: ")?;

    let mut db = Database::new();
    db.meta.database_name = Some("kpcli-rust test fixture".to_string());

    // Root-level entry.
    db.root_mut().add_entry().edit(|e| {
        e.set_unprotected(fields::TITLE, "rootlogin");
        e.set_unprotected(fields::USERNAME, "alice");
        e.set_protected(fields::PASSWORD, "rootpw-do-not-use");
        e.set_unprotected(fields::URL, "https://example.invalid/root");
    });

    // Email/personal
    db.root_mut()
        .add_group()
        .edit(|g| g.name = "Email".to_string())
        .add_entry()
        .edit(|e| {
            e.set_unprotected(fields::TITLE, "personal");
            e.set_unprotected(fields::USERNAME, "alice@example.invalid");
            e.set_protected(fields::PASSWORD, "correct-horse-battery-staple");
            e.set_unprotected(fields::NOTES, "primary mailbox");
        });

    // Servers/prod (separate group)
    db.root_mut()
        .add_group()
        .edit(|g| g.name = "Servers".to_string())
        .add_entry()
        .edit(|e| {
            e.set_unprotected(fields::TITLE, "prod-db");
            e.set_unprotected(fields::USERNAME, "ops");
            e.set_protected(fields::PASSWORD, "rotate-me-please");
            e.set_unprotected(fields::URL, "ssh://prod-db.internal");
        });

    db.save(
        &mut File::create(&path)?,
        DatabaseKey::new().with_password(&password),
    )?;
    println!("wrote fixture: {path}");
    Ok(())
}
