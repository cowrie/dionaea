// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: GPL-3.0-only
// ABOUTME: Privilege dropping after port binding.
// ABOUTME: Resolves user/group names, sets RLIMIT_NOFILE, drops uid/gid.

use nix::sys::resource::{self, Resource};
use nix::unistd::{Gid, Group, Uid, User};

/// Resolve a username to a UID. Accepts numeric IDs or names.
pub fn resolve_user(name: &str) -> Result<Uid, String> {
    if let Ok(uid) = name.parse::<u32>() {
        return Ok(Uid::from_raw(uid));
    }
    User::from_name(name)
        .map_err(|e| format!("failed to look up user '{name}': {e}"))?
        .map(|u| u.uid)
        .ok_or_else(|| format!("user '{name}' not found"))
}

/// Resolve a group name to a GID. Accepts numeric IDs or names.
pub fn resolve_group(name: &str) -> Result<Gid, String> {
    if let Ok(gid) = name.parse::<u32>() {
        return Ok(Gid::from_raw(gid));
    }
    Group::from_name(name)
        .map_err(|e| format!("failed to look up group '{name}': {e}"))?
        .map(|g| g.gid)
        .ok_or_else(|| format!("group '{name}' not found"))
}

/// Raise RLIMIT_NOFILE to the hard limit.
///
/// Honeypots handle many concurrent connections, so we want as many file
/// descriptors as possible. Returns the new soft limit.
pub fn raise_nofile_limit() -> Result<u64, String> {
    let (_, hard) = resource::getrlimit(Resource::RLIMIT_NOFILE)
        .map_err(|e| format!("getrlimit(NOFILE): {e}"))?;

    resource::setrlimit(Resource::RLIMIT_NOFILE, hard, hard)
        .map_err(|e| format!("setrlimit(NOFILE, {hard}): {e}"))?;

    tracing::info!(nofile_limit = hard, "raised RLIMIT_NOFILE to hard limit");
    Ok(hard)
}

/// Drop privileges to the specified user and group.
///
/// Must be called as root. Order: groups → gid → uid (changing uid last
/// ensures we still have permission to change gid and groups).
///
/// Returns Ok(()) on success, or if already running as the target user.
pub fn drop_privileges(uid: Uid, gid: Gid) -> Result<(), String> {
    let current_uid = Uid::current();
    let current_gid = Gid::current();

    // If already running as the target, nothing to do
    if current_uid == uid && current_gid == gid {
        tracing::info!(uid = uid.as_raw(), gid = gid.as_raw(), "already running as target user");
        return Ok(());
    }

    // Must be root to change uid/gid
    if !current_uid.is_root() {
        tracing::warn!(
            current_uid = current_uid.as_raw(),
            target_uid = uid.as_raw(),
            "not running as root, skipping privilege drop"
        );
        return Ok(());
    }

    // Drop supplementary groups (not available on macOS)
    #[cfg(not(target_os = "macos"))]
    nix::unistd::setgroups(&[gid])
        .map_err(|e| format!("setgroups: {e}"))?;

    // Drop group (before dropping user, since we need root to setgid)
    nix::unistd::setgid(gid)
        .map_err(|e| format!("setgid({}): {e}", gid.as_raw()))?;

    // Drop user (last, since this removes root privileges)
    nix::unistd::setuid(uid)
        .map_err(|e| format!("setuid({}): {e}", uid.as_raw()))?;

    tracing::info!(
        uid = uid.as_raw(),
        gid = gid.as_raw(),
        "dropped privileges"
    );

    // Verify we can't regain root
    if nix::unistd::setuid(Uid::from_raw(0)).is_ok() {
        return Err("SECURITY: was able to regain root after privilege drop!".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_user_numeric() {
        let uid = resolve_user("0").unwrap();
        assert_eq!(uid, Uid::from_raw(0));
    }

    #[test]
    fn test_resolve_user_root() {
        let uid = resolve_user("root").unwrap();
        assert_eq!(uid, Uid::from_raw(0));
    }

    #[test]
    fn test_resolve_user_not_found() {
        let err = resolve_user("nonexistent_user_xyzzy").unwrap_err();
        assert!(err.contains("not found"), "error: {err}");
    }

    #[test]
    fn test_resolve_group_numeric() {
        let gid = resolve_group("0").unwrap();
        assert_eq!(gid, Gid::from_raw(0));
    }

    #[test]
    fn test_resolve_group_by_name() {
        // "wheel" on macOS, "root" on Linux — try both
        let result = resolve_group("wheel").or_else(|_| resolve_group("root"));
        assert!(result.is_ok(), "should resolve wheel or root group");
    }

    #[test]
    fn test_resolve_group_not_found() {
        let err = resolve_group("nonexistent_group_xyzzy").unwrap_err();
        assert!(err.contains("not found"), "error: {err}");
    }

    #[test]
    fn test_raise_nofile_limit() {
        // Should succeed even as non-root (raising soft to hard is allowed)
        let limit = raise_nofile_limit().unwrap();
        assert!(limit > 0);
    }

    #[test]
    fn test_drop_privileges_already_target() {
        // When already running as the target user, should be a no-op
        let uid = Uid::current();
        let gid = Gid::current();
        drop_privileges(uid, gid).unwrap();
    }

    #[test]
    fn test_drop_privileges_not_root() {
        // When not root and target is different, should skip gracefully
        if Uid::current().is_root() {
            // Can't test this as root
            return;
        }
        let result = drop_privileges(Uid::from_raw(65534), Gid::from_raw(65534));
        assert!(result.is_ok(), "should skip gracefully when not root");
    }
}
