use anyhow::{Context, Result};
use keepass::{db::Database, DatabaseKey};
use std::path::Path;
use zeroize::Zeroizing;

/// Prompt for the master password without echoing, then open the KDBX4 file.
/// The password is held in a `Zeroizing<String>` so its bytes are scrubbed
/// from memory as soon as `open` returns.
pub fn open_interactive(path: &Path) -> Result<Database> {
    let password = Zeroizing::new(
        rpassword::prompt_password(format!("Master password for {}: ", path.display()))
            .context("reading master password")?,
    );
    open_with_password(path, &password)
}

pub fn open_with_password(path: &Path, password: &str) -> Result<Database> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("opening database file {}", path.display()))?;
    let key = DatabaseKey::new().with_password(password);
    Database::open(&mut file, key)
        .with_context(|| format!("decrypting {}", path.display()))
}
