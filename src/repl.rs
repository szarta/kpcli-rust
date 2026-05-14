use anyhow::Result;
use keepass::db::{Database, EntryRef, GroupRef};
// Note on lifetimes: keepass returns `GroupRef<'self>` from methods like
// `GroupRef::group_by_path`, where `'self` is the borrow of the intermediate
// `GroupRef`, not the underlying `&Database`. So to hand a `GroupRef<'a>`
// back to a caller (where `'a` is the database borrow), we extract the
// owned `GroupId` / `EntryId` and re-fetch via `Database::group` /
// `Database::entry`, both of which return refs tied to `&Database`.
use rustyline::{error::ReadlineError, DefaultEditor};
use std::path::Path;

use crate::db;

pub fn run(db_path: &Path) -> Result<()> {
    let database = db::open_interactive(db_path)?;
    let mut shell = Shell::new(database);
    shell.repl()
}

struct Shell {
    database: Database,
    /// Path of group names from the root group, not including the root itself.
    /// `cwd.is_empty()` means we are at the root.
    cwd: Vec<String>,
}

impl Shell {
    fn new(database: Database) -> Self {
        Self {
            database,
            cwd: Vec::new(),
        }
    }

    fn repl(&mut self) -> Result<()> {
        let mut rl = DefaultEditor::new()?;
        println!("kpcli-rust — type `help` for commands, `quit` to exit.");

        loop {
            let prompt = format!("kpcli:/{}> ", self.cwd.join("/"));
            match rl.readline(&prompt) {
                Ok(line) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let _ = rl.add_history_entry(line);
                    match self.dispatch(line) {
                        Ok(ControlFlow::Continue) => {}
                        Ok(ControlFlow::Exit) => break,
                        Err(e) => eprintln!("error: {e:#}"),
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    // Ctrl-C: clear the line, keep going.
                    continue;
                }
                Err(ReadlineError::Eof) => break,
                Err(e) => {
                    eprintln!("readline error: {e}");
                    break;
                }
            }
        }
        Ok(())
    }

    fn dispatch(&mut self, line: &str) -> Result<ControlFlow> {
        let mut parts = line.split_whitespace();
        let cmd = parts.next().unwrap_or("");
        let args: Vec<&str> = parts.collect();

        match cmd {
            "help" | "?" => {
                print_help();
                Ok(ControlFlow::Continue)
            }
            "pwd" => {
                println!("/{}", self.cwd.join("/"));
                Ok(ControlFlow::Continue)
            }
            "ls" => {
                self.cmd_ls(&args)?;
                Ok(ControlFlow::Continue)
            }
            "cd" => {
                self.cmd_cd(&args)?;
                Ok(ControlFlow::Continue)
            }
            "show" => {
                self.cmd_show(&args)?;
                Ok(ControlFlow::Continue)
            }
            "find" => {
                self.cmd_find(&args)?;
                Ok(ControlFlow::Continue)
            }
            "quit" | "exit" | "q" => Ok(ControlFlow::Exit),
            other => {
                eprintln!("unknown command: {other} (try `help`)");
                Ok(ControlFlow::Continue)
            }
        }
    }

    fn cwd_group(&self) -> Result<GroupRef<'_>> {
        cwd_group(&self.database, &self.cwd)
    }

    fn cmd_ls(&self, args: &[&str]) -> Result<()> {
        let group = if let Some(arg) = args.first() {
            let target = resolve_group_path(&self.database, &self.cwd, arg)?;
            target
        } else {
            self.cwd_group()?
        };

        let mut printed = false;
        for sub in group.groups() {
            println!("{}/", sub.name);
            printed = true;
        }
        for entry in group.entries() {
            println!("{}", entry.get_title().unwrap_or("<no title>"));
            printed = true;
        }
        if !printed {
            println!("(empty)");
        }
        Ok(())
    }

    fn cmd_cd(&mut self, args: &[&str]) -> Result<()> {
        let target = args.first().copied().unwrap_or("/");
        let new_cwd = resolve_cwd(&self.database, &self.cwd, target)?;
        self.cwd = new_cwd;
        Ok(())
    }

    fn cmd_show(&self, args: &[&str]) -> Result<()> {
        let mut show_password = false;
        let mut entry_arg: Option<&str> = None;
        for a in args {
            if *a == "-f" || *a == "--show-password" {
                show_password = true;
            } else if entry_arg.is_none() {
                entry_arg = Some(*a);
            } else {
                anyhow::bail!("show: unexpected argument {a}");
            }
        }
        let entry_arg = entry_arg.ok_or_else(|| anyhow::anyhow!("show: missing entry name"))?;
        let entry = resolve_entry(&self.database, &self.cwd, entry_arg)?;
        print_entry(&entry, show_password);
        Ok(())
    }

    fn cmd_find(&self, args: &[&str]) -> Result<()> {
        let needle = args
            .first()
            .ok_or_else(|| anyhow::anyhow!("find: missing query"))?
            .to_lowercase();
        let mut hits = 0usize;
        for entry in self.database.iter_all_entries() {
            if entry_matches(&entry, &needle) {
                println!("{}", entry_full_path(&entry));
                hits += 1;
            }
        }
        if hits == 0 {
            println!("(no matches)");
        }
        Ok(())
    }
}

enum ControlFlow {
    Continue,
    Exit,
}

fn print_help() {
    println!(
        "commands:
  help                    show this help
  pwd                     print current group path
  ls [path]               list groups and entries (current group by default)
  cd <path>               change to group; / for root, .. for parent
  show <entry> [-f]       print entry fields; -f to reveal password
  find <query>            search entries (title/username/url/notes, case-insensitive)
  quit | exit             leave the shell"
    );
}

fn cwd_group<'a>(db: &'a Database, cwd: &[String]) -> Result<GroupRef<'a>> {
    if cwd.is_empty() {
        return Ok(db.root());
    }
    let parts: Vec<&str> = cwd.iter().map(|s| s.as_str()).collect();
    let id = db
        .root()
        .group_by_path(&parts)
        .ok_or_else(|| {
            anyhow::anyhow!("current group path no longer exists: /{}", cwd.join("/"))
        })?
        .id();
    db.group(id).ok_or_else(|| {
        anyhow::anyhow!("group id no longer exists for /{}", cwd.join("/"))
    })
}

fn resolve_cwd(db: &Database, cwd: &[String], target: &str) -> Result<Vec<String>> {
    let mut path: Vec<String> = if target.starts_with('/') {
        Vec::new()
    } else {
        cwd.to_vec()
    };
    for component in target.split('/') {
        match component {
            "" | "." => continue,
            ".." => {
                path.pop();
            }
            name => path.push(name.to_string()),
        }
    }

    // Validate the resulting path actually points at a real group.
    let root = db.root();
    let parts: Vec<&str> = path.iter().map(|s| s.as_str()).collect();
    if parts.is_empty() {
        return Ok(path);
    }
    root.group_by_path(&parts)
        .ok_or_else(|| anyhow::anyhow!("no such group: /{}", path.join("/")))?;
    Ok(path)
}

fn resolve_group_path<'a>(
    db: &'a Database,
    cwd: &[String],
    target: &str,
) -> Result<GroupRef<'a>> {
    let path = resolve_cwd(db, cwd, target)?;
    cwd_group(db, &path)
}

fn resolve_entry<'a>(
    db: &'a Database,
    cwd: &[String],
    target: &str,
) -> Result<EntryRef<'a>> {
    // Split into "parent group path" + "entry name".
    let absolute = target.starts_with('/');
    let mut parts: Vec<&str> = target.split('/').filter(|p| !p.is_empty()).collect();
    let entry_name = parts
        .pop()
        .ok_or_else(|| anyhow::anyhow!("show: empty entry name"))?;

    let parent_path: Vec<String> = if absolute {
        parts.iter().map(|s| s.to_string()).collect()
    } else {
        let mut p = cwd.to_vec();
        for c in parts {
            match c {
                "." => {}
                ".." => {
                    p.pop();
                }
                name => p.push(name.to_string()),
            }
        }
        p
    };

    let group = cwd_group(db, &parent_path)?;
    let entry_id = group
        .entry_by_name(entry_name)
        .ok_or_else(|| anyhow::anyhow!("no such entry: {entry_name}"))?
        .id();
    db.entry(entry_id)
        .ok_or_else(|| anyhow::anyhow!("entry id no longer exists: {entry_name}"))
}

fn entry_matches(entry: &EntryRef<'_>, needle_lc: &str) -> bool {
    for field in ["Title", "UserName", "URL", "Notes"] {
        if let Some(v) = entry.get(field) {
            if v.to_lowercase().contains(needle_lc) {
                return true;
            }
        }
    }
    false
}

fn entry_full_path(entry: &EntryRef<'_>) -> String {
    // Walk up via owned `GroupId`s so each iteration's `GroupRef` is borrowed
    // anew from the database — `GroupRef::parent` returns a ref tied to its
    // receiver, which is too short-lived to thread through a loop directly.
    let db = entry.database();
    let mut chain: Vec<String> = Vec::new();
    let mut current = Some(entry.parent().id());
    while let Some(id) = current {
        let group = match db.group(id) {
            Some(g) => g,
            None => break,
        };
        if group.parent().is_none() {
            break; // reached the root group; do not include its name
        }
        chain.push(group.name.clone());
        current = group.parent().map(|p| p.id());
    }
    chain.reverse();
    let prefix = if chain.is_empty() {
        String::from("/")
    } else {
        format!("/{}/", chain.join("/"))
    };
    format!("{prefix}{}", entry.get_title().unwrap_or("<no title>"))
}

fn print_entry(entry: &EntryRef<'_>, show_password: bool) {
    let title = entry.get_title().unwrap_or("<no title>");
    println!("Title:    {title}");
    if let Some(v) = entry.get_username() {
        println!("Username: {v}");
    }
    if let Some(v) = entry.get_url() {
        println!("URL:      {v}");
    }
    if let Some(v) = entry.get("Notes") {
        println!("Notes:    {v}");
    }
    match entry.get_password() {
        Some(p) if show_password => println!("Password: {p}"),
        Some(_) => println!("Password: <hidden — pass -f to reveal>"),
        None => println!("Password: <none>"),
    }
}

pub fn show_oneshot(db_path: &Path, entry_path: &str, show_password: bool) -> Result<()> {
    let database = db::open_interactive(db_path)?;
    let entry = resolve_entry(&database, &[], entry_path)?;
    print_entry(&entry, show_password);
    Ok(())
}

pub fn find_oneshot(db_path: &Path, query: &str) -> Result<()> {
    let database = db::open_interactive(db_path)?;
    let needle = query.to_lowercase();
    let mut hits = 0usize;
    for entry in database.iter_all_entries() {
        if entry_matches(&entry, &needle) {
            println!("{}", entry_full_path(&entry));
            hits += 1;
        }
    }
    if hits == 0 {
        println!("(no matches)");
    }
    Ok(())
}
