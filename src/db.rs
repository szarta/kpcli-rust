use anyhow::{Context, Result};
use keepass::{
    config::{DatabaseConfig, KdfConfig, OuterCipherConfig},
    db::Database,
    error::{DatabaseKeyError, DatabaseOpenError},
    DatabaseKey,
};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Decrypted database plus the master password it was opened with. The
/// password is retained for the lifetime of the [`OpenedDb`] so the REPL can
/// re-encrypt on `save` without re-prompting; both are dropped (and the
/// password's bytes zeroed) when the REPL exits.
pub struct OpenedDb {
    pub database: Database,
    pub password: Zeroizing<String>,
}

/// Prompt for the master password without echoing and open the KDBX4 file.
pub fn open_interactive(path: &Path) -> Result<OpenedDb> {
    let password = Zeroizing::new(
        rpassword::prompt_password(format!("Master password for {}: ", path.display()))
            .context("reading master password")?,
    );
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("opening database file {}", path.display()))?;
    let key = DatabaseKey::new().with_password(&password);
    let database = Database::open(&mut file, key).map_err(|e| friendly_open_error(e, path))?;
    Ok(OpenedDb { database, password })
}

/// Translate a [`DatabaseOpenError`] into a user-facing message. The KDBX4
/// format has no flag for "this database needs a keyfile" — a wrong
/// password and a missing keyfile produce the *same* HMAC failure
/// (`DatabaseKeyError::IncorrectKey`). Enumerate the possibilities instead
/// of pretending we can distinguish them.
fn friendly_open_error(err: DatabaseOpenError, path: &Path) -> anyhow::Error {
    if matches!(err, DatabaseOpenError::Key(DatabaseKeyError::IncorrectKey)) {
        return anyhow::anyhow!(
            "could not decrypt {}. One of:\n  \
             - the master password is wrong\n  \
             - the database is protected with a keyfile (kpcli-rust does not \
             support keyfiles by design; see README \"Deliberately out of scope\")\n  \
             - the database file is corrupted",
            path.display()
        );
    }
    anyhow::Error::new(err).context(format!("decrypting {}", path.display()))
}

/// Create a fresh KDBX4 database at `path`. Refuses to overwrite. Prompts
/// twice for the new master password (confirm). Uses Argon2id + ChaCha20.
pub fn init_interactive(path: &Path) -> Result<()> {
    if path.exists() {
        anyhow::bail!("refusing to overwrite existing file: {}", path.display());
    }

    let password = Zeroizing::new(
        rpassword::prompt_password(format!("New master password for {}: ", path.display()))
            .context("reading master password")?,
    );
    let confirm = Zeroizing::new(
        rpassword::prompt_password("Confirm master password: ")
            .context("reading password confirmation")?,
    );
    if *password != *confirm {
        anyhow::bail!("passwords do not match");
    }
    if password.is_empty() {
        anyhow::bail!("refusing to create a database with an empty password");
    }

    let mut config = DatabaseConfig::default();
    config.outer_cipher_config = OuterCipherConfig::ChaCha20;
    config.kdf_config = KdfConfig::Argon2id {
        // IMPORTANT: keepass-rs interprets `memory` as BYTES and converts to
        // KiB internally (mem_cost = memory / 1024). 1 GiB is intentionally
        // expensive — this is a password store, not a hot loop. The integration
        // tests assert this value end-to-end via the persisted KDF config; do
        // not lower it without also updating tests and the README.
        iterations: 50,
        memory: 1024 * 1024 * 1024,
        parallelism: 4,
        version: argon2::Version::Version13,
    };

    let mut database = Database::with_config(config);
    if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
        database.meta.database_name = Some(name.to_string());
    }

    // Save through the same atomic path the REPL uses, so init mirrors
    // production write semantics.
    save_atomic(&mut database, path, &password)?;
    println!("created: {} (Argon2id + ChaCha20)", path.display());
    Ok(())
}

/// Returned by [`save_atomic`] so callers can report where the backup landed.
pub struct SaveOutcome {
    pub backup: Option<PathBuf>,
}

/// Save a database to `path` with the given password, with a crash-safe
/// rename sequence:
///
/// 1. Encrypt and write to `<path>.tmp` (fsync before close).
/// 2. If `<path>` exists, rename it to `<path>.bak`.
/// 3. Rename `<path>.tmp` to `<path>` (atomic within the same filesystem).
///
/// A crash between (2) and (3) leaves the previous DB at `.bak`; a crash
/// between (1) and (2) leaves the original intact and a leftover `.tmp`.
pub fn save_atomic(
    database: &mut Database,
    path: &Path,
    password: &str,
) -> Result<SaveOutcome> {
    let tmp_path = sibling_with_suffix(path, "tmp")?;
    let bak_path = sibling_with_suffix(path, "bak")?;

    if tmp_path.exists() {
        anyhow::bail!(
            "stale {} from a previous interrupted save; inspect and remove before retrying",
            tmp_path.display()
        );
    }

    {
        use std::io::Write;
        let mut opts = std::fs::File::options();
        // `create_new` errors out instead of clobbering — guards against TOCTOU
        // between the `.exists()` check above and the actual create.
        opts.write(true).create_new(true);
        // 0600 at creation time so a stat() race during save cannot expose a
        // group/world-readable password file (umask alone is not enough).
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp_path)
            .with_context(|| format!("creating {}", tmp_path.display()))?;
        let key = DatabaseKey::new().with_password(password);
        database
            .save(&mut f, key)
            .with_context(|| format!("encrypting and writing {}", tmp_path.display()))?;
        f.flush()?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp_path.display()))?;
    }

    let backup = if path.exists() {
        std::fs::rename(path, &bak_path)
            .with_context(|| format!("renaming {} -> {}", path.display(), bak_path.display()))?;
        // The original may have come from a migration where it was already
        // group-readable; normalize the backup explicitly so we never leave a
        // permissive copy behind.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bak_path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod 0600 {}", bak_path.display()))?;
        }
        Some(bak_path)
    } else {
        None
    };

    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("renaming {} -> {}", tmp_path.display(), path.display()))?;

    Ok(SaveOutcome { backup })
}

fn sibling_with_suffix(path: &Path, suffix: &str) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("path has no file name: {}", path.display()))?
        .to_owned();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut name = file_name;
    name.push(".");
    name.push(suffix);
    Ok(parent.join(name))
}
