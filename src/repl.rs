use anyhow::Result;
use keepass::db::{fields, Database, EntryRef, GroupRef};
use rustyline::{error::ReadlineError, DefaultEditor};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::db::{self, OpenedDb};

// Note on lifetimes: keepass returns `GroupRef<'self>` from methods like
// `GroupRef::group_by_path`, where `'self` is the borrow of the intermediate
// `GroupRef`, not the underlying `&Database`. So to hand a `GroupRef<'a>`
// back to a caller (where `'a` is the database borrow), we extract the
// owned `GroupId` / `EntryId` and re-fetch via `Database::group` /
// `Database::entry`, both of which return refs tied to `&Database`.

pub fn run(db_path: &Path) -> Result<()> {
    let OpenedDb { database, password } = db::open_interactive(db_path)?;
    let mut shell = Shell {
        database,
        db_path: db_path.to_path_buf(),
        password,
        cwd: Vec::new(),
        dirty: false,
    };
    shell.repl()
}

struct Shell {
    database: Database,
    db_path: PathBuf,
    /// Master password held for the lifetime of the REPL session so `save`
    /// can re-encrypt without re-prompting. Bytes are zeroed on drop.
    password: Zeroizing<String>,
    /// Group names from the root, not including the root. Empty = at root.
    cwd: Vec<String>,
    /// Set by any mutating command; cleared by `save`. Quit warns if set.
    dirty: bool,
}

enum ControlFlow {
    Continue,
    Exit,
}

impl Shell {
    fn repl(&mut self) -> Result<()> {
        let mut rl = DefaultEditor::new()?;
        // Deliberately no command history: nothing is loaded from disk on
        // start, nothing is added to rustyline's in-memory ring during the
        // session, and nothing is written on exit. kpcli-rust is intended
        // to leave no record of usage on the host filesystem.
        println!("kpcli-rust — type `help` for commands, `quit` to exit.");

        loop {
            let prompt = format!(
                "kpcli:/{}{}> ",
                self.cwd.join("/"),
                if self.dirty { " *" } else { "" }
            );
            match rl.readline(&prompt) {
                Ok(line) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    // No `rl.add_history_entry` — see comment above the
                    // `DefaultEditor::new` call for rationale.
                    match self.dispatch(line) {
                        Ok(ControlFlow::Continue) => {}
                        Ok(ControlFlow::Exit) => break,
                        Err(e) => eprintln!("error: {e:#}"),
                    }
                }
                Err(ReadlineError::Interrupted) => continue, // Ctrl-C
                Err(ReadlineError::Eof) => {
                    if self.dirty {
                        eprintln!(
                            "\nkpcli-rust: exiting with unsaved changes (Ctrl-D); changes were NOT written"
                        );
                    }
                    break;
                }
                Err(e) => {
                    eprintln!("readline error: {e}");
                    break;
                }
            }
        }
        Ok(())
    }

    fn dispatch(&mut self, line: &str) -> Result<ControlFlow> {
        // We parse manually rather than via clap to keep the per-command UX
        // (e.g. "rest of line is the value" for `set`) under our control.
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
            "mkgroup" => {
                self.cmd_mkgroup(&args)?;
                Ok(ControlFlow::Continue)
            }
            "add" => {
                self.cmd_add(&args)?;
                Ok(ControlFlow::Continue)
            }
            "set" => {
                self.cmd_set(line, &args)?;
                Ok(ControlFlow::Continue)
            }
            "rm" => {
                self.cmd_rm(&args)?;
                Ok(ControlFlow::Continue)
            }
            "mv" => {
                self.cmd_mv(&args)?;
                Ok(ControlFlow::Continue)
            }
            "save" => {
                self.cmd_save()?;
                Ok(ControlFlow::Continue)
            }
            "quit" | "exit" | "q" => self.handle_quit(false),
            "quit!" | "exit!" => self.handle_quit(true),
            other => {
                eprintln!("unknown command: {other} (try `help`)");
                Ok(ControlFlow::Continue)
            }
        }
    }

    fn handle_quit(&self, force: bool) -> Result<ControlFlow> {
        if self.dirty && !force {
            eprintln!("unsaved changes — `save` first, or use `quit!` to discard");
            Ok(ControlFlow::Continue)
        } else {
            Ok(ControlFlow::Exit)
        }
    }

    // ---- read-only commands ------------------------------------------------

    fn cmd_ls(&self, args: &[&str]) -> Result<()> {
        let group = if let Some(arg) = args.first() {
            resolve_group_path(&self.database, &self.cwd, arg)?
        } else {
            cwd_group(&self.database, &self.cwd)?
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

    // ---- mutating commands -------------------------------------------------

    fn cmd_mkgroup(&mut self, args: &[&str]) -> Result<()> {
        let name = args
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("mkgroup: missing group name"))?;
        if name.contains('/') {
            anyhow::bail!("mkgroup: name must not contain '/'");
        }

        // Existence check via immutable borrow, scoped tightly so we can take
        // a mutable borrow afterward.
        {
            let g = cwd_group(&self.database, &self.cwd)?;
            if g.group_by_name(name).is_some() {
                anyhow::bail!("group already exists: {name}");
            }
        }

        let mut parent = self.cwd_group_mut()?;
        let mut new_group = parent.add_group();
        new_group.name = name.to_string();
        self.dirty = true;
        println!("created group: {name}");
        Ok(())
    }

    fn cmd_add(&mut self, args: &[&str]) -> Result<()> {
        let title = args
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("add: missing entry title"))?;
        if title.contains('/') {
            anyhow::bail!("add: title must not contain '/' (use cd into the group first)");
        }

        // Existence check first, before mutable borrow.
        {
            let g = cwd_group(&self.database, &self.cwd)?;
            if g.entry_by_name(title).is_some() {
                anyhow::bail!("entry already exists: {title}");
            }
        }

        // Collect field values. Each prompt accepts `.` on its own line
        // (or EOF / Ctrl-D) to abort the whole add without creating the
        // entry. Password goes through rpassword so it never echoes.
        let username = match prompt_line_or_abort("Username (blank to skip, '.' to abort): ")? {
            Some(v) => v,
            None => {
                println!("(add aborted; no entry created)");
                return Ok(());
            }
        };
        let password = match prompt_password_or_abort(
            "Password (blank to skip, '.' to abort, hidden): ",
        )? {
            Some(v) => v,
            None => {
                println!("(add aborted; no entry created)");
                return Ok(());
            }
        };
        let url = match prompt_line_or_abort("URL (blank to skip, '.' to abort): ")? {
            Some(v) => v,
            None => {
                println!("(add aborted; no entry created)");
                return Ok(());
            }
        };
        let notes = match prompt_line_or_abort("Notes (blank to skip, '.' to abort): ")? {
            Some(v) => v,
            None => {
                println!("(add aborted; no entry created)");
                return Ok(());
            }
        };

        let mut parent = self.cwd_group_mut()?;
        let mut e = parent.add_entry();
        e.set_unprotected(fields::TITLE, title);
        if !username.is_empty() {
            e.set_unprotected(fields::USERNAME, username);
        }
        if !password.is_empty() {
            e.set_protected(fields::PASSWORD, password.as_str());
        }
        if !url.is_empty() {
            e.set_unprotected(fields::URL, url);
        }
        if !notes.is_empty() {
            e.set_unprotected(fields::NOTES, notes);
        }
        drop(e);

        self.dirty = true;
        println!("added entry: {title}");
        Ok(())
    }

    fn cmd_set(&mut self, full_line: &str, args: &[&str]) -> Result<()> {
        // Syntax:
        //   set <entry> <field> <value...>     # value is rest-of-line
        //   set <entry> password               # always prompts (no inline)
        let entry_name = args
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("set: missing entry name"))?;
        let field_raw = args
            .get(1)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("set: missing field name"))?;
        let field = canonical_field(field_raw)
            .ok_or_else(|| anyhow::anyhow!("set: unknown field {field_raw} (one of: title/username/password/url/notes)"))?;

        // Look up entry id via immutable side.
        let entry_id = {
            let entry = resolve_entry(&self.database, &self.cwd, entry_name)?;
            entry.id()
        };

        let is_password = field == fields::PASSWORD;

        if is_password {
            if args.len() > 2 {
                anyhow::bail!(
                    "set: refusing to take a password on the command line; \
                     `set {entry_name} password` will prompt"
                );
            }
            let new_password = Zeroizing::new(rpassword::prompt_password("New password: ")?);
            let confirm = Zeroizing::new(rpassword::prompt_password("Confirm: ")?);
            if *new_password != *confirm {
                anyhow::bail!("passwords do not match");
            }
            let mut e = self
                .database
                .entry_mut(entry_id)
                .ok_or_else(|| anyhow::anyhow!("entry id no longer exists"))?;
            e.set_protected(fields::PASSWORD, new_password.as_str());
        } else {
            // Reconstruct value from the raw line so spaces/quotes survive.
            let value = extract_value_after(full_line, entry_name, field_raw)?;
            let mut e = self
                .database
                .entry_mut(entry_id)
                .ok_or_else(|| anyhow::anyhow!("entry id no longer exists"))?;
            if value.is_empty() {
                // Empty value clears the field by setting it to "" — keepass
                // does not expose a removal API for standard fields, and
                // empty is the conventional "no value" representation.
                e.set_unprotected(field, "");
            } else {
                e.set_unprotected(field, value);
            }
        }

        self.dirty = true;
        println!("updated: {entry_name}.{}", canonical_field_name(field));
        Ok(())
    }

    fn cmd_rm(&mut self, args: &[&str]) -> Result<()> {
        let mut recursive = false;
        let mut name: Option<&str> = None;
        for a in args {
            match *a {
                "-r" | "--recursive" => recursive = true,
                other => {
                    if name.is_some() {
                        anyhow::bail!("rm: unexpected argument {other}");
                    }
                    name = Some(other);
                }
            }
        }
        let name = name.ok_or_else(|| anyhow::anyhow!("rm: missing name"))?;
        if name.contains('/') {
            anyhow::bail!("rm: name must not contain '/' (cd into the group first)");
        }

        // Decide: is it an entry, a group, neither?
        enum Kind {
            Entry(keepass::db::EntryId),
            Group {
                id: keepass::db::GroupId,
                child_count: usize,
            },
        }
        let kind = {
            let g = cwd_group(&self.database, &self.cwd)?;
            if let Some(e) = g.entry_by_name(name) {
                Kind::Entry(e.id())
            } else if let Some(sub) = g.group_by_name(name) {
                let child_count = sub.groups().count() + sub.entries().count();
                Kind::Group {
                    id: sub.id(),
                    child_count,
                }
            } else {
                anyhow::bail!("no such entry or group at cwd: {name}");
            }
        };

        match kind {
            Kind::Entry(id) => {
                let e = self
                    .database
                    .entry_mut(id)
                    .ok_or_else(|| anyhow::anyhow!("entry id no longer exists"))?;
                e.remove();
                println!("removed entry: {name}");
            }
            Kind::Group { id, child_count } => {
                if child_count > 0 && !recursive {
                    anyhow::bail!(
                        "rm: {name}/ is not empty ({child_count} children); pass `-r` to delete recursively"
                    );
                }
                let g = self
                    .database
                    .group_mut(id)
                    .ok_or_else(|| anyhow::anyhow!("group id no longer exists"))?;
                g.remove();
                println!("removed group: {name}/");
            }
        }
        self.dirty = true;
        Ok(())
    }

    fn cmd_mv(&mut self, args: &[&str]) -> Result<()> {
        // Syntax:
        //   mv <name> <new-name>            # rename within the current group
        //   mv <name> <path/>               # move INTO an existing group, keep name
        //   mv <name> <path/new-name>       # move + rename to <path/new-name>
        //
        // Trailing slash on the destination forces the "move into" reading,
        // disambiguating from a same-named rename. Bare names always mean
        // rename in place, even if a group with that name happens to exist
        // in the cwd (entries and groups share neither namespace nor lookup
        // path in this CLI — too ambiguous to guess).
        let src_name = args
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("mv: missing source name"))?;
        let dst = args
            .get(1)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("mv: missing destination"))?;
        if src_name.contains('/') {
            anyhow::bail!("mv: source name must not contain '/' (cd into the group first)");
        }

        enum Src {
            Entry(keepass::db::EntryId),
            Group(keepass::db::GroupId),
        }
        // Capture the current parent's id alongside the source id, so we
        // can later decide whether a `move_to` is necessary without
        // touching the mutable side.
        let (src, src_parent_id) = {
            let g = cwd_group(&self.database, &self.cwd)?;
            let parent_id = g.id();
            if let Some(e) = g.entry_by_name(src_name) {
                (Src::Entry(e.id()), parent_id)
            } else if let Some(sub) = g.group_by_name(src_name) {
                (Src::Group(sub.id()), parent_id)
            } else {
                anyhow::bail!("no such entry or group at cwd: {src_name}");
            }
        };

        let trailing_slash = dst.ends_with('/');
        let (target_parent_path, new_name) = if trailing_slash {
            let trimmed = dst.trim_end_matches('/');
            // A bare "/" means root.
            let parent_path = if trimmed.is_empty() {
                Vec::new()
            } else {
                resolve_cwd(&self.database, &self.cwd, trimmed)?
            };
            (parent_path, src_name.to_string())
        } else if let Some(idx) = dst.rfind('/') {
            let parent_str = &dst[..idx];
            let new_name = &dst[idx + 1..];
            if new_name.is_empty() {
                anyhow::bail!("mv: destination must end in a name or have a trailing '/'");
            }
            let parent_path = if parent_str.is_empty() {
                // "/name" — destination parent is root.
                Vec::new()
            } else {
                resolve_cwd(&self.database, &self.cwd, parent_str)?
            };
            (parent_path, new_name.to_string())
        } else {
            (self.cwd.clone(), dst.to_string())
        };

        if new_name.is_empty() || new_name == "." || new_name == ".." {
            anyhow::bail!("mv: invalid destination name {new_name:?}");
        }
        if new_name.contains('/') {
            anyhow::bail!("mv: destination name must not contain '/'");
        }

        // Reject self-move (no-op): same parent, same name.
        if target_parent_path == self.cwd && new_name == src_name {
            anyhow::bail!("mv: source and destination are the same");
        }

        let pretty_dst = if target_parent_path.is_empty() {
            format!("/{new_name}")
        } else {
            format!("/{}/{new_name}", target_parent_path.join("/"))
        };

        // Collision check + grab the target parent group id.
        let target_parent_id = {
            let g = cwd_group(&self.database, &target_parent_path)?;
            if g.entry_by_name(&new_name).is_some() || g.group_by_name(&new_name).is_some() {
                anyhow::bail!("mv: destination {pretty_dst} already exists");
            }
            g.id()
        };

        let need_move = src_parent_id != target_parent_id;
        match src {
            Src::Entry(id) => {
                let mut e = self
                    .database
                    .entry_mut(id)
                    .ok_or_else(|| anyhow::anyhow!("entry id no longer exists"))?;
                if need_move {
                    e.move_to(target_parent_id)
                        .map_err(|err| anyhow::anyhow!("mv: {err:?}"))?;
                }
                e.set_unprotected(fields::TITLE, &new_name);
            }
            Src::Group(id) => {
                let mut g = self
                    .database
                    .group_mut(id)
                    .ok_or_else(|| anyhow::anyhow!("group id no longer exists"))?;
                if need_move {
                    g.move_to(target_parent_id)
                        .map_err(|err| anyhow::anyhow!("mv: {err:?}"))?;
                }
                g.name = new_name;
            }
        }

        self.dirty = true;
        println!("moved: {src_name} -> {pretty_dst}");
        Ok(())
    }

    fn cmd_save(&mut self) -> Result<()> {
        let outcome = db::save_atomic(&mut self.database, &self.db_path, &self.password)?;
        self.dirty = false;
        match outcome.backup {
            Some(bak) => println!(
                "saved: {} (backup: {})",
                self.db_path.display(),
                bak.display()
            ),
            None => println!("saved: {} (no previous file)", self.db_path.display()),
        }
        Ok(())
    }

    // ---- mutable cwd lookup ------------------------------------------------

    fn cwd_group_mut(&mut self) -> Result<keepass::db::GroupMut<'_>> {
        if self.cwd.is_empty() {
            return Ok(self.database.root_mut());
        }
        // Get the GroupId via the immutable side first, so the immutable
        // borrow ends before we take a mutable one. `root_mut().group_by_path_mut`
        // would return a ref tied to the temporary `root_mut()`, not the db.
        let id = {
            let parts: Vec<&str> = self.cwd.iter().map(|s| s.as_str()).collect();
            self.database
                .root()
                .group_by_path(&parts)
                .ok_or_else(|| {
                    anyhow::anyhow!("cwd no longer exists: /{}", self.cwd.join("/"))
                })?
                .id()
        };
        self.database.group_mut(id).ok_or_else(|| {
            anyhow::anyhow!("group id no longer exists for /{}", self.cwd.join("/"))
        })
    }
}

// ---- pure helpers ---------------------------------------------------------

fn print_help() {
    println!(
        "commands:
  help                          show this help
  pwd                           print current group path
  ls [path]                     list groups and entries

read:
  cd <path>                     change group; / for root, .. for parent
  show <entry> [-f]             print entry fields; -f to reveal password
  find <query>                  case-insensitive search across Title/UserName/URL/Notes

edit:
  mkgroup <name>                create a new group at cwd
  add <title>                   create a new entry at cwd; prompts for fields
  set <entry> <field> <value>   update title/username/url/notes; rest of line is the value
  set <entry> password          re-prompt for a new password (hidden, confirmed)
  rm [-r] <name>                delete entry or (with -r) a group
  mv <name> <dst>               rename in place (<dst> bare), or move into a group
                                (<dst> ends with '/'), or move + rename (<dst> with slashes)
  save                          backup-on-save: writes .tmp, renames original to .bak,
                                then renames .tmp into place

exit:
  quit | exit                   leave; warns if unsaved changes
  quit! | exit!                 force-quit, discarding unsaved changes"
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
    let absolute = target.starts_with('/');
    let mut parts: Vec<&str> = target.split('/').filter(|p| !p.is_empty()).collect();
    let entry_name = parts
        .pop()
        .ok_or_else(|| anyhow::anyhow!("empty entry name"))?;

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
    for field in [fields::TITLE, fields::USERNAME, fields::URL, fields::NOTES] {
        if let Some(v) = entry.get(field) {
            if v.to_lowercase().contains(needle_lc) {
                return true;
            }
        }
    }
    false
}

fn entry_full_path(entry: &EntryRef<'_>) -> String {
    let db = entry.database();
    let mut chain: Vec<String> = Vec::new();
    let mut current = Some(entry.parent().id());
    while let Some(id) = current {
        let group = match db.group(id) {
            Some(g) => g,
            None => break,
        };
        if group.parent().is_none() {
            break;
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
    if let Some(v) = entry.get(fields::NOTES) {
        println!("Notes:    {v}");
    }
    match entry.get_password() {
        Some(p) if show_password => println!("Password: {p}"),
        Some(_) => println!("Password: <hidden — pass -f to reveal>"),
        None => println!("Password: <none>"),
    }

    // Any non-canonical fields the DB carries (TOTP secrets, custom
    // attributes, etc.). KDBX entries can hold arbitrary key/value pairs,
    // and a database imported from KeePassXC routinely will. We treat
    // protected custom fields with the same -f gate as the password.
    //
    // `keepass` stores fields in a HashMap — iteration order is
    // non-deterministic; collect and sort for a stable display.
    let mut extras: Vec<(&String, &keepass::db::Value<String>)> = entry
        .fields
        .iter()
        .filter(|(k, _)| {
            ![
                fields::TITLE,
                fields::USERNAME,
                fields::PASSWORD,
                fields::URL,
                fields::NOTES,
            ]
            .contains(&k.as_str())
        })
        .collect();
    extras.sort_by(|a, b| a.0.cmp(b.0));
    for (key, value) in extras {
        if value.is_protected() && !show_password {
            println!("{key}: <hidden — pass -f to reveal>");
        } else {
            println!("{key}: {}", value.get());
        }
    }
}

/// Map user-typed field shorthand to the canonical KDBX field name.
fn canonical_field(name: &str) -> Option<&'static str> {
    match name.to_ascii_lowercase().as_str() {
        "title" | "t" => Some(fields::TITLE),
        "username" | "user" | "u" => Some(fields::USERNAME),
        "password" | "pw" | "pass" | "p" => Some(fields::PASSWORD),
        "url" | "uri" => Some(fields::URL),
        "notes" | "note" | "n" => Some(fields::NOTES),
        _ => None,
    }
}

fn canonical_field_name(field: &str) -> &str {
    field
}

/// Given the original input line and the already-parsed `entry` and `field`
/// tokens, return everything after them (with leading whitespace trimmed).
/// Used by `set` so values can contain whitespace without quoting.
fn extract_value_after(line: &str, entry: &str, field: &str) -> Result<String> {
    // The line begins with the command itself; skip past `set <entry> <field>`.
    // Tokens are whitespace-separated, but we want to preserve internal spacing
    // in the *value*, so we find substring positions instead of re-splitting.
    let after_cmd = line
        .trim_start()
        .strip_prefix("set")
        .ok_or_else(|| anyhow::anyhow!("internal: set parser called on non-set line"))?
        .trim_start();
    let after_entry = after_cmd
        .strip_prefix(entry)
        .ok_or_else(|| anyhow::anyhow!("internal: could not relocate entry token"))?
        .trim_start();
    let after_field = after_entry
        .strip_prefix(field)
        .ok_or_else(|| anyhow::anyhow!("internal: could not relocate field token"))?
        .trim_start();
    Ok(after_field.to_string())
}

/// Read a line from stdin with a prompt. Returns `Ok(None)` if the user
/// wants to abort the surrounding flow — signalled by a line containing
/// only `.` or by EOF (Ctrl-D / closed stdin).
fn prompt_line_or_abort(prompt: &str) -> Result<Option<String>> {
    use std::io::Write;
    let mut out = std::io::stdout();
    out.write_all(prompt.as_bytes())?;
    out.flush()?;
    let mut s = String::new();
    let n = std::io::stdin().read_line(&mut s)?;
    if n == 0 {
        // EOF before any input — treat as abort.
        println!();
        return Ok(None);
    }
    let trimmed = s.trim_end_matches('\n').trim_end_matches('\r');
    if trimmed == "." {
        return Ok(None);
    }
    Ok(Some(trimmed.to_string()))
}

/// Like [`prompt_line_or_abort`] but reads from `/dev/tty` without
/// echoing, via `rpassword`. The same `.` and EOF abort semantics apply.
fn prompt_password_or_abort(prompt: &str) -> Result<Option<Zeroizing<String>>> {
    match rpassword::prompt_password(prompt) {
        Ok(s) => {
            if s == "." {
                Ok(None)
            } else {
                Ok(Some(Zeroizing::new(s)))
            }
        }
        // rpassword maps an EOF on /dev/tty to UnexpectedEof; treat that
        // the same way as a `.` so the caller can bail cleanly.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            println!();
            Ok(None)
        }
        Err(e) => Err(anyhow::Error::from(e)),
    }
}

pub fn show_oneshot(db_path: &Path, entry_path: &str, show_password: bool) -> Result<()> {
    let OpenedDb { database, .. } = db::open_interactive(db_path)?;
    let entry = resolve_entry(&database, &[], entry_path)?;
    print_entry(&entry, show_password);
    Ok(())
}

pub fn find_oneshot(db_path: &Path, query: &str) -> Result<()> {
    let OpenedDb { database, .. } = db::open_interactive(db_path)?;
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
