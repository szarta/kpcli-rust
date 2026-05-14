# kpcli-rust

An offline-only command-line client for KeePass KDBX4 databases.

The shipped binary opens a network socket exactly **never**. That property is
enforced by three independent mechanisms — see [Security model](#security-model)
below.

## Status

Read-only. Open a database, navigate it, search it, print entries. Edit and
save are deliberately not built into the shipped binary; see
[Scope](#deliberately-out-of-scope).

## Install

```bash
cargo build --release
# binary at target/release/kpcli-rust
```

Requires a recent Rust toolchain (developed against 1.90).

## Use

### Interactive shell (kpcli-style)

```bash
kpcli-rust /path/to/db.kdbx
# or:  kpcli-rust open /path/to/db.kdbx
```

You will be prompted for the master password on `/dev/tty`. The REPL accepts:

| command            | what it does                                                       |
| ------------------ | ------------------------------------------------------------------ |
| `help` / `?`       | list commands                                                      |
| `pwd`              | print the current group path                                       |
| `ls [path]`        | list groups (`name/`) and entries in the current or given group    |
| `cd <path>`        | change group; `/` for root, `..` for parent, absolute or relative  |
| `show <entry> [-f]`| print entry fields; `-f` reveals the password instead of hiding it |
| `find <query>`     | case-insensitive substring search over Title / UserName / URL / Notes |
| `quit` / `exit`    | leave the shell                                                    |

### One-shot subcommands

```bash
kpcli-rust show /path/to/db.kdbx /Email/personal       # password hidden
kpcli-rust show /path/to/db.kdbx /Email/personal -f    # password revealed
kpcli-rust find /path/to/db.kdbx prod
```

Each one-shot re-prompts for the master password — there is no agent, no
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

- **Edit / save.** The `keepass` crate's `save_kdbx4` feature is enabled
  only for `examples/make_fixture.rs`, behind a `fixture` cargo feature.
  It is never compiled into the shipped binary.
- **KDBX3 / legacy v1 `.kdb`.** KDBX4 only.
- **Keyfiles, YubiKey challenge-response, TOTP.**
- **Clipboard / auto-type / browser integration.**
- **Reading the master password from stdin or an env var.** Removes a
  scripting footgun and forces the password to come from `/dev/tty`.

## Layout

```
.
├── Cargo.toml
├── deny.toml
├── examples/
│   └── make_fixture.rs   # cargo run --features fixture --example make_fixture -- <path> <pw>
└── src/
    ├── main.rs           # CLI dispatch; calls sandbox::lockdown() first
    ├── sandbox.rs        # seccomp-bpf filter + selftest
    ├── db.rs             # KDBX4 open with zeroized master-password buffer
    └── repl.rs           # interactive shell + one-shot show/find
```

## License

MIT OR Apache-2.0.
