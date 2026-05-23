use anyhow::{Context, Result};
use keepass::{
    config::{DatabaseConfig, KdfConfig, OuterCipherConfig},
    db::Database,
    error::{DatabaseKeyError, DatabaseOpenError},
    DatabaseKey,
};
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Decrypted database plus the master password it was opened with. The
/// password is retained for the lifetime of the [`OpenedDb`] so the REPL can
/// re-encrypt on `save` without re-prompting; both are dropped (and the
/// password's bytes zeroed) when the REPL exits.
pub struct OpenedDb {
    pub database: Database,
    pub password: Zeroizing<String>,
    /// (dev, ino) of the database file at open time, on Unix. Used by
    /// `save_atomic` to detect another process having replaced the file
    /// between open and save — a lightweight alternative to advisory
    /// flock that avoids leaving a `.lock` sidecar on disk. `None` on
    /// non-Unix or if metadata could not be read.
    pub open_fs_id: Option<(u64, u64)>,
}

/// Read the (dev, ino) pair for `path` if available. Used to detect
/// concurrent saves on the same database (see [`save_atomic`]).
#[cfg(unix)]
fn fs_id_of(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))
}
#[cfg(not(unix))]
fn fs_id_of(_: &Path) -> Option<(u64, u64)> {
    None
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
    let open_fs_id = fs_id_of(path);
    Ok(OpenedDb {
        database,
        password,
        open_fs_id,
    })
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
    println!("Passwords matched.");

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

    // Argon2id at 1 GiB / 50 iterations takes several seconds on first
    // run; print a status line (with an explicit flush, since there is no
    // trailing newline) so the user sees that work is in progress rather
    // than a frozen terminal.
    print!("Generating database (Argon2id KDF, ~1 GiB memory; this may take several seconds)... ");
    std::io::stdout().flush().ok();

    // Save through the same atomic path the REPL uses, so init mirrors
    // production write semantics. There is no prior file, so no expected
    // fs-id to assert against.
    save_atomic(&mut database, path, &password, None)?;
    println!("done.");
    println!("created: {} (Argon2id + ChaCha20)", path.display());
    Ok(())
}

/// Returned by [`save_atomic`] so callers can report where the backup
/// landed and update their open-time fs-id snapshot for the next save.
pub struct SaveOutcome {
    pub backup: Option<PathBuf>,
    /// (dev, ino) of the freshly written database file. The REPL stores
    /// this so the next save can detect a concurrent kpcli-rust that
    /// replaced the file in the meantime.
    pub new_fs_id: Option<(u64, u64)>,
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
///
/// `expected_fs_id` is the (dev, ino) the caller recorded at open time
/// (or after the previous save). If it does not match the file at `path`
/// right now, another process has saved over it — refuse rather than
/// silently clobbering. Pass `None` to skip the check (e.g. the initial
/// save during `init` where no prior file existed).
pub fn save_atomic(
    database: &mut Database,
    path: &Path,
    password: &str,
    expected_fs_id: Option<(u64, u64)>,
) -> Result<SaveOutcome> {
    let tmp_path = sibling_with_suffix(path, "tmp")?;
    let bak_path = sibling_with_suffix(path, "bak")?;

    if tmp_path.exists() {
        anyhow::bail!(
            "stale {} from a previous interrupted save; inspect and remove before retrying",
            tmp_path.display()
        );
    }

    // Concurrent-save guard: if the file on disk no longer matches the
    // (dev, ino) the caller recorded at open time, another kpcli-rust
    // (or some other writer) has replaced it. Refuse rather than
    // overwrite their work. The user can quit and reopen to integrate.
    //
    // `expected_fs_id == None` means the caller (init) expects no prior
    // file. If we find one, an attacker (or another process) materialized
    // the path during init's Argon2id derivation window — refuse so we
    // don't silently rename their file to `<db>.bak`.
    match (expected_fs_id, fs_id_of(path)) {
        (Some(expected), Some(actual)) if actual != expected => {
            anyhow::bail!(
                "{} was modified by another process since it was opened; \
                 `quit!` (discarding changes here) and reopen to pick up the new version",
                path.display()
            );
        }
        (None, Some(_)) => {
            anyhow::bail!(
                "{} was created during init by another process; aborting (try a different path)",
                path.display()
            );
        }
        // Either matches, or no file exists at the path, or metadata read
        // failed — let the subsequent file ops surface a clearer error.
        _ => {}
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
        // Close the late-window TOCTOU: at the start of save_atomic we
        // verified there was no prior file (init case) or that the prior
        // file's fs-id matched (save case). The Argon2id derivation that
        // just finished took multiple seconds; a foreign file could have
        // materialized in that window. For the init case we refuse
        // outright; for the save case we re-verify fs-id has not changed
        // mid-flight before silently treating the file as "ours".
        match (expected_fs_id, fs_id_of(path)) {
            (None, _) => {
                let _ = std::fs::remove_file(&tmp_path);
                anyhow::bail!(
                    "{} materialized during init; aborting before we would have renamed \
                     a foreign file to {}.bak",
                    path.display(),
                    path.display()
                );
            }
            (Some(expected), Some(actual)) if actual != expected => {
                let _ = std::fs::remove_file(&tmp_path);
                anyhow::bail!(
                    "{} was replaced by another process during save; aborting before clobber. \
                     `quit!` and reopen to integrate.",
                    path.display()
                );
            }
            _ => {}
        }

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

    let new_fs_id = fs_id_of(path);
    Ok(SaveOutcome { backup, new_fs_id })
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
