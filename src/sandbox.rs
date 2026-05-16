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
        // io_uring (Linux 5.1+, IORING_OP_SOCKET added in 5.19) dispatches
        // its operations inside the kernel without re-entering the syscall
        // table, so blocking SYS_socket alone is not enough — a dependency
        // could submit IORING_OP_SOCKET + IORING_OP_CONNECT + IORING_OP_SEND
        // entirely through io_uring_enter and reach the network. Block the
        // entire io_uring entry surface.
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ];

    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for &sc in blocked {
        // Empty rule vec = match this syscall regardless of arguments.
        rules.insert(sc, vec![]);
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

/// Probe the sandbox by attempting forbidden syscalls and confirming each
/// is denied. Exits non-zero if any unexpectedly succeeds.
#[cfg(target_os = "linux")]
pub fn selftest() -> anyhow::Result<()> {
    // Probe 1: classic socket() — the historical network entry point.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd >= 0 {
        unsafe { libc::close(fd) };
        anyhow::bail!(
            "selftest FAILED: socket(AF_INET, SOCK_STREAM) succeeded — sandbox is NOT in effect"
        );
    }
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if errno != libc::EACCES {
        anyhow::bail!(
            "selftest FAILED: socket() denied with errno {errno} but expected EACCES ({})",
            libc::EACCES
        );
    }

    // Probe 2: io_uring_setup — modern bypass. A dep that builds an
    // io_uring instance can issue IORING_OP_SOCKET / OP_CONNECT / OP_SEND
    // entirely inside io_uring_enter without ever hitting socket(2). We
    // forbid the entire io_uring entry surface; this probe verifies that.
    //
    // io_uring_setup signature: int io_uring_setup(u32 entries, struct io_uring_params *p)
    let mut params: [u8; 120] = [0; 120]; // io_uring_params is < 120 bytes on every arch
    let rc = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1u32, params.as_mut_ptr()) };
    if rc >= 0 {
        // Don't actually try to close — if the kernel returned a real fd
        // it means our filter failed; print and exit.
        anyhow::bail!(
            "selftest FAILED: io_uring_setup succeeded (rc={rc}) — sandbox does NOT block io_uring"
        );
    }
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    // Some kernels return ENOSYS if CONFIG_IO_URING=n. That's also fine
    // — the syscall is unreachable for any reason. EACCES is what we
    // installed; accept either.
    if errno != libc::EACCES && errno != libc::ENOSYS {
        anyhow::bail!(
            "selftest FAILED: io_uring_setup denied with errno {errno} \
             but expected EACCES ({}) or ENOSYS ({})",
            libc::EACCES,
            libc::ENOSYS
        );
    }

    println!(
        "selftest OK: socket(AF_INET) and io_uring_setup both blocked, as expected."
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn selftest() -> anyhow::Result<()> {
    anyhow::bail!("selftest: runtime sandbox is only available on Linux");
}
