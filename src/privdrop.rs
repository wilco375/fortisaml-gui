//! Give up root after the tunnel is set up: become the user who ran pkexec, keeping only CAP_NET_ADMIN (enough to
//! tear the tunnel down again) and CAP_KILL (to stop the root charon at the end), and forbid gaining privileges back
//! through exec. Capabilities and NO_NEW_PRIVS are per thread: the drop applies to the calling (main) thread, which
//! does all the privileged work; the other threads only read pipes.

/// `PKEXEC_UID` as set by pkexec for the program it runs.
pub fn pkexec_uid() -> Result<u32, String> {
    let v = std::env::var("PKEXEC_UID").map_err(|_| "PKEXEC_UID is not set (not started through pkexec)".to_string())?;
    let uid: u32 = v.parse().map_err(|_| format!("bad PKEXEC_UID {v:?}"))?;
    if uid == 0 {
        return Err("PKEXEC_UID is 0: refusing to keep running as root".into());
    }
    Ok(uid)
}

const CAP_KILL: u32 = 5;
const CAP_NET_ADMIN: u32 = 12;
/// The capabilities kept after the drop.
pub const KEPT_CAPS: u32 = (1 << CAP_NET_ADMIN) | (1 << CAP_KILL);
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Switch to `uid` and its primary group, keeping only `KEPT_CAPS`. Must be called while still root.
pub fn drop_to(uid: u32) -> Result<(), String> {
    let err = |what: &str| format!("dropping privileges: {what}: {}", std::io::Error::last_os_error());
    // SAFETY: plain libc calls on our own process; getpwuid_r writes only into the buffers we pass
    unsafe {
        let mut pw: libc::passwd = std::mem::zeroed();
        let mut buf = vec![0 as libc::c_char; 4096];
        let mut res: *mut libc::passwd = std::ptr::null_mut();
        if libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut res) != 0 || res.is_null() {
            return Err(format!("dropping privileges: no user with uid {uid}"));
        }
        let gid = pw.pw_gid;
        // keep the permitted capability set across setuid, so CAP_NET_ADMIN can be re-raised below
        if libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0 {
            return Err(err("PR_SET_KEEPCAPS"));
        }
        if libc::setgroups(0, std::ptr::null()) != 0 {
            return Err(err("setgroups"));
        }
        if libc::setresgid(gid, gid, gid) != 0 {
            return Err(err("setresgid"));
        }
        if libc::setresuid(uid, uid, uid) != 0 {
            return Err(err("setresuid"));
        }
        let mut hdr = CapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
        let data = [CapData { effective: KEPT_CAPS, permitted: KEPT_CAPS, inheritable: 0 }, CapData::default()];
        if libc::syscall(libc::SYS_capset, &mut hdr as *mut CapHeader, data.as_ptr()) != 0 {
            return Err(err("capset"));
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(err("PR_SET_NO_NEW_PRIVS"));
        }
        // a root that could come back would undo all of the above
        if libc::setuid(0) == 0 {
            return Err("dropping privileges: could become root again".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_net_admin_and_kill_only() {
        // CAP_KILL: to stop the root charon (SIGTERM, and PDEATHSIG delivery) after the drop
        assert_eq!(KEPT_CAPS, (1 << 12) | (1 << 5));
    }

    #[test]
    fn pkexec_uid_rules() {
        // SAFETY: test-only env changes; these tests don't run in parallel with others reading PKEXEC_UID
        unsafe { std::env::set_var("PKEXEC_UID", "1000") };
        assert_eq!(pkexec_uid(), Ok(1000));
        unsafe { std::env::set_var("PKEXEC_UID", "0") };
        assert!(pkexec_uid().is_err());
        unsafe { std::env::set_var("PKEXEC_UID", "x") };
        assert!(pkexec_uid().is_err());
        unsafe { std::env::remove_var("PKEXEC_UID") };
        assert!(pkexec_uid().is_err());
    }
}
