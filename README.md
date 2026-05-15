# kpcli-rust

An offline-only command-line client for KeePass KDBX4 databases.

The shipped binary opens a network socket exactly **never**. That property is
enforced by three independent mechanisms — see [Security model](#security-model)
below.

## Status

Create, open, navigate, search, edit, save. All operations are local —
the binary never opens a network socket.

## Install

```bash
cargo build --release
# binary at target/release/kpcli-rust
```

Requires a recent Rust toolchain (developed against 1.90).

## Use

### Create a new database

```bash
kpcli-rust init /path/to/new.kdbx
# prompts twice for the master password; refuses to overwrite an existing file.
# Crypto: Argon2id (50 iters, 1 GiB memory, 4-way parallelism) + ChaCha20.
```

The first save is slow on purpose — that is the Argon2id derivation. On
subsequent opens the cost is paid once per session.

### Interactive shell (kpcli-style)

```bash
kpcli-rust /path/to/db.kdbx
# or:  kpcli-rust open /path/to/db.kdbx
```

You will be prompted for the master password on `/dev/tty`. The REPL has a
`*` after the group path when there are unsaved changes.

The REPL keeps **no command history** — nothing is loaded at startup,
nothing is recorded during the session, nothing is written on exit. This
is intentional so the tool leaves no trace of usage on the host
filesystem (relevant when the binary is run inside an encrypted volume
and the outside view must not reveal what was looked up). The rustyline
`with-file-history` feature is not enabled in `Cargo.toml`.

**Read commands**

| command            | what it does                                                       |
| ------------------ | ------------------------------------------------------------------ |
| `help` / `?`       | list commands                                                      |
| `pwd`              | print the current group path                                       |
| `ls [path]`        | list groups (`name/`) and entries in the current or given group    |
| `cd <path>`        | change group; `/` for root, `..` for parent, absolute or relative  |
| `show <entry> [-f]`| print entry fields (canonical + any custom string fields); `-f` reveals the password and any protected custom fields |
| `find <query>`     | case-insensitive substring search over Title / UserName / URL / Notes |

**Edit commands**

| command                       | what it does                                                                 |
| ----------------------------- | ---------------------------------------------------------------------------- |
| `mkgroup <name>`              | create a new subgroup at the current group                                   |
| `add <title>`                 | create a new entry at the current group; prompts for username/password/url/notes. Type `.` (or Ctrl-D) at any prompt to abort without creating the entry. |
| `set <entry> <field> <value>` | update `title` / `username` / `url` / `notes`; everything after the field is the value (no quoting required) |
| `set <entry> password`        | re-prompt for a new password (hidden, confirmed); inline password is refused |
| `rm <name>`                   | delete an entry or an empty group at the current group                       |
| `rm -r <name>`                | delete a group recursively                                                   |
| `mv <name> <dst>`             | rename in place (`<dst>` bare), move into an existing group (`<dst>` trailing `/`), or move + rename (`<dst>` with slashes). Refuses to overwrite. |
| `save`                        | persist changes — see [Save semantics](#save-semantics) below                |

**Exit**

| command           | what it does                                                  |
| ----------------- | ------------------------------------------------------------- |
| `quit` / `exit`   | leave; refuses if there are unsaved changes                   |
| `quit!` / `exit!` | leave, discarding unsaved changes                             |

### Save semantics

`save` is crash-safe by construction:

1. The database is encrypted and written to `<db>.tmp`. The file is
   `fsync`'d before close.
2. If `<db>` exists, it is renamed to `<db>.bak`.
3. `<db>.tmp` is renamed to `<db>`.

Both renames are atomic within a single filesystem. A crash between (2)
and (3) leaves the previous database at `.bak`. A crash between (1) and
(2) leaves the original intact and a leftover `.tmp` (the next `save`
refuses to proceed until you remove it).

`save` re-encrypts using the master password that opened the session —
no extra prompt. The password is held in a `Zeroizing<String>` for the
lifetime of the REPL and zeroed on exit.

On Unix the new database and its `.bak` are written with mode `0600`,
regardless of umask. If you migrate an existing world- or group-readable
KDBX into kpcli-rust, the first `save` will normalize the backup to
`0600` as well.

### One-shot subcommands

```bash
kpcli-rust show /path/to/db.kdbx /Email/personal       # password hidden
kpcli-rust show /path/to/db.kdbx /Email/personal -f    # password revealed
kpcli-rust find /path/to/db.kdbx prod
```

One-shot subcommands are **read-only** by design — there is no
`kpcli-rust add` / `set` / `rm` / `save`. Edits happen only from inside
the REPL, so a misfiring shell loop cannot clobber a database. Each
one-shot re-prompts for the master password; there is no agent, no
session, and no cached key on disk.

### Verify the sandbox

```bash
kpcli-rust selftest
# selftest OK: socket(AF_INET) blocked with EACCES, as expected.
```

Run this after every build and after kernel / glibc upgrades. A failed
selftest means the runtime layer of the no-network guarantee is missing for
this binary on this kernel — investigate before opening a real database.

## Security model

### Threat model

- **In scope:** a malicious or compromised third-party crate (direct or
  transitive) attempting to exfiltrate database contents, the master
  password, or environment data over the network.
- **In scope:** accidental network use by a future maintainer (`cargo add
  reqwest` for some unrelated feature).
- **Out of scope:** a hostile local user with code execution as you, a
  malicious kernel, side channels (CPU, memory, timing), and physical
  attacks on the host.

### What the binary will not do

It will not open a network socket, resolve a hostname, connect to any
host, listen on any port, or send/receive on a socket. It will not copy
passwords to the clipboard (`xclip`/`wl-copy`/etc. are not linked).

### Layers

The three layers below are independent. The audit is the primary
guarantee; cargo-deny mechanizes it; seccomp is belt-and-suspenders for
when one of the first two fails.

#### 1. Dependency audit

The `keepass` crate is depended on with `default-features = false`. Its
default feature set is already empty, but pinning it makes that explicit.
The full resolved tree contains crypto (aes / chacha20 / hmac / sha2 /
argon2 / blake2 / cipher), compression (flate2 / miniz_oxide), XML
parsing (quick-xml), terminal I/O (rustyline / rpassword / nix), CLI
parsing (clap), error handling (anyhow / thiserror), and on Linux
seccompiler + libc. There is no HTTP client, no TLS stack, no async
runtime, no DNS resolver, and no `socket2` / `mio`.

Verify locally:

```bash
cargo tree --edges normal | grep -Ei \
    'reqwest|hyper|tokio|ureq|isahc|curl|rustls|native-tls|openssl|mio|socket2|hickory|trust-dns'
# expected: no output
```

#### 2. `cargo-deny` enforcement

`deny.toml` bans every HTTP client, TLS stack, DNS resolver, async
runtime, and socket-abstraction crate by name. The list is conservative
and biased toward false positives — adding a banned crate must be a
deliberate, reviewable decision, not a silent transitive pickup.

```bash
cargo install cargo-deny      # one-time
cargo deny check bans         # run on every CI build
```

#### 3. seccomp-bpf runtime sandbox (Linux)

`main` calls `sandbox::lockdown` before parsing arguments or touching the
filesystem. It installs a seccomp filter with action `Allow` for every
syscall *except* the network entry points, which return `EACCES`:

- `socket`, `connect`, `bind`, `listen`, `accept`, `accept4`
- `sendto`, `sendmsg`, `sendmmsg`
- `recvfrom`, `recvmsg`, `recvmmsg`
- `setsockopt`, `getsockopt`, `getsockname`, `getpeername`, `shutdown`

A network operation typically starts with `socket(AF_INET, ...)` →
`connect(...)`. Blocking `socket` alone forecloses every TCP, UDP, and
raw-IP path; the rest are belt-and-suspenders against any creative
descriptor inheritance or pre-opened socket scenario.

`socketpair(2)` is **not** blocked. The Linux kernel only permits
`AF_UNIX` for `socketpair`, so it cannot create a network endpoint;
rustyline relies on it for internal I/O.

On non-Linux platforms `lockdown` is a no-op and prints a warning to
stderr. The dependency audit still applies, but the runtime layer does
not. Treat this as a degraded mode and prefer running on Linux for
sensitive use.

### Why "no clipboard"

A clipboard integration requires linking against an X11 / Wayland /
macOS-Pasteboard crate. Each of those is a meaningful expansion of the
attack surface (and on Linux, `xclip` etc. typically need socket
permissions we have just removed). kpcli-rust prints the password to the
terminal when you pass `-f` and leaves the rest to you.

### Master password handling

The master password is read with `rpassword` (no echo, from `/dev/tty`)
into a `Zeroizing<String>` whose bytes are scrubbed when the string is
dropped — which happens before the REPL loop starts. The decrypted
database itself is held in memory while the program runs; exit (or
`quit`) drops it. There is no on-disk caching.

## Deliberately out of scope

These are *not* present, by design. Adding any of them is a deliberate
decision that should be re-evaluated against the threat model.

- **Edit / save from one-shot subcommands.** Mutation is REPL-only —
  `kpcli-rust add` / `set` / `rm` / `save` do not exist. The
  `keepass/save_kdbx4` feature is on, but the only way to reach a
  mutating call path from a shell script is to interactively drive the
  REPL.
- **KDBX3 / legacy v1 `.kdb`.** KDBX4 only.
- **Keyfiles, YubiKey challenge-response, TOTP.**
- **Clipboard / auto-type / browser integration.**
- **Reading the master password from stdin or an env var.** Removes a
  scripting footgun and forces the password to come from `/dev/tty`.
- **Password generation.** Bring your own.

## Layout

```
.
├── Cargo.toml
├── deny.toml
├── examples/
│   └── make_fixture.rs   # cargo run --example make_fixture -- <path> <pw>
└── src/
    ├── main.rs           # CLI dispatch; calls sandbox::lockdown() first
    ├── sandbox.rs        # seccomp-bpf filter + selftest
    ├── db.rs             # KDBX4 open / init / save_atomic; zeroized master-password buffer
    └── repl.rs           # interactive shell (read + edit) + one-shot read commands
```

## License

MIT OR Apache-2.0.
