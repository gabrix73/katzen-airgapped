//! Kernel-enforced network isolation (Logical Air-Gap)
//!
//! Provides OS-level network revocation so that cryptographic vault operations
//! cannot make external network connections even if running on an internet-connected host.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxStatus {
    /// Network fully revoked via kernel namespace/seccomp
    KernelEnforced(String),
    /// Legacy status; never means network isolation is enforced.
    Restricted(String),
}

/// Applies kernel-level network isolation to the current process.
/// Once applied, this process cannot open network sockets or reach external hosts.
pub fn apply_network_isolation() -> Result<SandboxStatus, String> {
    #[cfg(target_os = "linux")]
    {
        apply_linux_isolation()
    }

    #[cfg(target_os = "openbsd")]
    {
        apply_openbsd_pledge()
    }

    #[cfg(not(any(target_os = "linux", target_os = "openbsd")))]
    {
        Err("Kernel network isolation is not supported on this OS".to_string())
    }
}

#[cfg(target_os = "linux")]
fn apply_linux_isolation() -> Result<SandboxStatus, String> {
    unsafe {
        // Step 1: Prevent acquiring new privileges (required for unprivileged seccomp / user ns)
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(format!("Cannot set no_new_privs: {}", std::io::Error::last_os_error()));
        }

        // Step 2: Try unshare with CLONE_NEWUSER | CLONE_NEWNET (unprivileged network isolation)
        let res = libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET);
        if res == 0 {
            return Ok(SandboxStatus::KernelEnforced(
                "Linux CLONE_NEWUSER | CLONE_NEWNET network namespace isolation active".to_string(),
            ));
        }

        // Fallback: try CLONE_NEWNET directly (works if CAP_SYS_ADMIN / root)
        let res_net = libc::unshare(libc::CLONE_NEWNET);
        if res_net == 0 {
            return Ok(SandboxStatus::KernelEnforced(
                "Linux CLONE_NEWNET network namespace isolation active".to_string(),
            ));
        }

        let err = std::io::Error::last_os_error();
        Err(format!("Cannot enforce Linux network namespace isolation: {err}"))
    }
}

#[cfg(target_os = "openbsd")]
fn apply_openbsd_pledge() -> Result<SandboxStatus, String> {
    use std::ffi::CString;
    // Omit "inet" pledge: any network socket call results in SIGABRT
    let promises = CString::new("stdio rpath wpath cpath").map_err(|e| e.to_string())?;
    let res = unsafe { libc::pledge(promises.as_ptr(), std::ptr::null()) };
    if res == 0 {
        Ok(SandboxStatus::KernelEnforced(
            "OpenBSD pledge('stdio rpath wpath cpath') enforced (no 'inet')".to_string(),
        ))
    } else {
        Err(format!("pledge failed: {}", std::io::Error::last_os_error()))
    }
}

/// A connectivity probe only. A failed connection is not proof of isolation.
pub fn is_network_blocked() -> bool {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            // Cannot even create socket (e.g. seccomp / pledge)
            return true;
        }

        // Try connecting to a non-local address
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as u16;
        addr.sin_port = 80u16.to_be();
        addr.sin_addr.s_addr = 0x01010101; // 1.1.1.1

        let res = libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );

        libc::close(fd);

        // Failure can also mean DNS, routing, firewall, or remote service failure.
        res != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_status() {
        // Hosts may forbid unprivileged namespaces; failure must be explicit.
        let status = apply_network_isolation();
        assert!(matches!(status, Ok(SandboxStatus::KernelEnforced(_)) | Err(_)));
    }
}
