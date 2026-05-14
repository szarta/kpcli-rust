// Runtime defense-in-depth: on Linux, install a seccomp-bpf filter that
// denies every syscall used to open a network connection. The dependency
// audit (deny.toml) is the primary guarantee; this is the belt to that
// suspenders, so a malicious or compromised dependency cannot quietly
// reach the network at runtime.
//
// Allow-by-default is intentional: we only need to forbid the network
// surface, not the entire syscall table.

#[cfg(target_os = "linux")]
pub fn lockdown() -> anyhow::Result<()> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
    use std::collections::BTreeMap;

    // Note: `socketpair(2)` is intentionally *not* blocked. Per the Linux
    // manpage it only supports AF_UNIX; the kernel rejects any other domain.
    // It is local IPC, not network, and rustyline relies on it internally.
    // `socket(2)` itself remains blocked, which is the actual network entry
    // point (AF_INET/AF_INET6/AF_PACKET/AF_NETLINK, etc.).
    let blocked: &[libc::c_long] = &[
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_shutdown,
    ];

    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for &sc in blocked {
        // Empty rule vec = match this syscall regardless of arguments.
        rules.insert(sc as i64, vec![]);
    }

    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|e: seccompiler::BackendError| anyhow::anyhow!("unsupported arch: {e}"))?;

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,                       // default for everything else
        SeccompAction::Errno(libc::EACCES as u32),  // for the network syscalls above
        arch,
    )?;
    let program: BpfProgram = filter.try_into()?;
    seccompiler::apply_filter(&program)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn lockdown() -> anyhow::Result<()> {
    // No seccomp on non-Linux platforms. The dependency audit still applies,
    // but make it loud so the user is not silently weaker than they expect.
    eprintln!(
        "kpcli-rust: warning: runtime network sandbox unavailable on this platform; \
         relying on dependency audit only"
    );
    Ok(())
}

/// Probe the sandbox by attempting a forbidden syscall and confirming it is
/// denied. Exits non-zero if the syscall unexpectedly succeeds.
#[cfg(target_os = "linux")]
pub fn selftest() -> anyhow::Result<()> {
    // SAFETY: AF_INET/SOCK_STREAM is a benign syscall; we close any returned
    // descriptor immediately and assert it should never succeed in the first
    // place because lockdown() has been applied.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
        anyhow::bail!(
            "selftest FAILED: socket(AF_INET, SOCK_STREAM) succeeded — sandbox is NOT in effect"
        );
    }
    let errno = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(0);
    if errno != libc::EACCES {
        anyhow::bail!(
            "selftest FAILED: socket() denied with errno {errno} but expected EACCES ({})",
            libc::EACCES
        );
    }
    println!("selftest OK: socket(AF_INET) blocked with EACCES, as expected.");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn selftest() -> anyhow::Result<()> {
    anyhow::bail!("selftest: runtime sandbox is only available on Linux");
}
