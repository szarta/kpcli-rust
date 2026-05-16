mod db;
mod repl;
mod sandbox;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "kpcli-rust",
    version,
    about = "Offline-only command-line KeePass (KDBX4) client",
    long_about = "kpcli-rust never opens a network socket. On Linux this is enforced \
                  at runtime via a seccomp-bpf filter installed before any database \
                  bytes are read. Dependencies are audited via cargo-deny (see deny.toml)."
)]
struct Cli {
    /// Database file (KDBX4). If given without a subcommand, starts the REPL.
    db: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new empty KDBX4 database at the given path (Argon2id + ChaCha20).
    Init {
        db: PathBuf,
    },
    /// Open a database and start the interactive shell.
    Open {
        db: PathBuf,
    },
    /// Show a single entry by path, e.g. /Email/personal.
    Show {
        db: PathBuf,
        path: String,
        /// Print the password in cleartext instead of hiding it.
        #[arg(short = 'f', long)]
        show_password: bool,
    },
    /// Search the database for entries matching a substring.
    Find {
        db: PathBuf,
        query: String,
    },
    /// Verify the runtime network sandbox is in effect (Linux only).
    /// Attempts to open a network socket; expects EACCES.
    Selftest,
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("kpcli-rust: {e:#}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    // Lock down BEFORE we touch any user input or the database file, so a
    // bug or surprise dependency cannot phone home during startup.
    sandbox::lockdown()?;

    let cli = Cli::parse();
    match cli.command {
        Some(Command::Init { db }) => db::init_interactive(&db),
        Some(Command::Open { db }) => repl::run(&db),
        Some(Command::Show {
            db,
            path,
            show_password,
        }) => repl::show_oneshot(&db, &path, show_password),
        Some(Command::Find { db, query }) => repl::find_oneshot(&db, &query),
        Some(Command::Selftest) => sandbox::selftest(),
        None => match cli.db {
            Some(db) => repl::run(&db),
            None => {
                use clap::CommandFactory;
                Cli::command().print_help()?;
                println!();
                std::process::exit(2);
            }
        },
    }
}
