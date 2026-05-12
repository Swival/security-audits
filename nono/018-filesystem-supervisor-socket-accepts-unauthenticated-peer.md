# filesystem supervisor socket accepts unauthenticated peer

## Classification

Authentication bypass, medium severity.

## Affected Locations

`crates/nono/src/supervisor/socket.rs:83`

## Summary

`SupervisorSocket::bind()` accepted the first process that connected to a filesystem Unix socket and returned it as the trusted supervisor IPC peer without authenticating the peer. A same-UID local process that could access the socket path could race the intended sandbox child, connect first, and become the capability-expansion IPC peer.

`bind()` is a public library API and is currently not used by `nono-cli` itself (the in-tree supervisor uses `SupervisorSocket::pair()`, which inherits the peer through fork and is not exposed to other processes). The vulnerable code is reachable only through external library consumers that opt into the filesystem-socket flavor. The fix still belongs in the library: as a sandbox primitive it should not hand out an unauthenticated peer to any caller of this API.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Supervisor IPC uses the filesystem socket bind path.
- An attacker-controlled same-UID local process can access the socket path.
- The attacker can connect before the intended sandbox child.

## Proof

`SupervisorSocket::bind()` created a restricted Unix listener, called `listener.accept()`, and immediately wrapped the first accepted `UnixStream` as a `SupervisorSocket`.

No `SO_PEERCRED`, peer PID, UID, parent PID, session, or namespace validation was performed before returning the socket. Existing credential helpers such as `peer_credentials()`, `peer_pid()`, and `peer_in_same_user_namespace()` existed but were not used by `bind()`.

The accepted stream is security-sensitive: supervisor message handling processes `SupervisorMessage::Request`, delegates approval, opens requested paths, and sends granted file descriptors via `sock.send_fd()`. Therefore, the unauthenticated peer could send capability-expansion or URL-open messages as if it were the sandbox child.

## Why This Is A Real Bug

Filesystem permissions of `0700` only limit access to the owning UID. They do not distinguish the intended child process from any other same-UID process. Since `bind()` trusted whichever peer connected first, authentication depended on a race rather than on peer identity.

This differs from anonymous socketpair IPC, where the peer is inherited through process creation, and from attach socket handling that explicitly authenticates peers.

## Fix Requirement

Authenticate the accepted filesystem socket peer before returning it as a `SupervisorSocket`.

The accepted peer must be verified against expected local process properties, including UID, process relationship, and user namespace where supported.

## Patch Rationale

The patch calls `authenticate_supervisor_peer(stream.as_raw_fd())?` immediately after `listener.accept()` and before constructing the returned `SupervisorSocket`.

`authenticate_supervisor_peer()` now verifies:

- The peer UID matches the supervisor effective UID.
- The peer parent PID is the current supervisor PID.
- The peer is in the same user namespace where supported.

The patch adds platform-specific parent PID lookup:

- Linux: parses `/proc/<pid>/status` for `PPid`.
- macOS: uses `proc_pidinfo(PROC_PIDTBSDINFO)`.
- Other platforms: returns unsupported rather than silently accepting unauthenticated peers.

This converts the previous first-connector-wins behavior into an explicit peer authentication step.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono/src/supervisor/socket.rs b/crates/nono/src/supervisor/socket.rs
index 69cfe36..09f98e4 100644
--- a/crates/nono/src/supervisor/socket.rs
+++ b/crates/nono/src/supervisor/socket.rs
@@ -92,6 +92,7 @@ impl SupervisorSocket {
         let (stream, _addr) = listener.accept().map_err(|e| {
             NonoError::SandboxInit(format!("Failed to accept supervisor connection: {e}"))
         })?;
+        authenticate_supervisor_peer(stream.as_raw_fd())?;
 
         Ok(SupervisorSocket {
             stream,
@@ -456,6 +457,110 @@ pub fn peer_credentials(sock_fd: RawFd) -> Result<PeerCredentials> {
     }
 }
 
+fn authenticate_supervisor_peer(sock_fd: RawFd) -> Result<()> {
+    let peer = peer_credentials(sock_fd)?;
+    let current_uid = unsafe { libc::geteuid() } as u32;
+    let current_pid = std::process::id();
+    let peer_parent = peer_parent_pid(peer.pid)?;
+
+    if peer.uid != current_uid {
+        Err(NonoError::SandboxInit(format!(
+            "supervisor peer uid {} does not match current uid {}",
+            peer.uid, current_uid
+        )))
+    } else if peer_parent != current_pid {
+        Err(NonoError::SandboxInit(format!(
+            "supervisor peer pid {} is not a child of current pid {}",
+            peer.pid, current_pid
+        )))
+    } else if !peer_in_same_user_namespace(peer.pid)? {
+        Err(NonoError::SandboxInit(format!(
+            "supervisor peer pid {} is not in the current user namespace",
+            peer.pid
+        )))
+    } else {
+        Ok(())
+    }
+}
+
+#[cfg(target_os = "linux")]
+fn peer_parent_pid(peer_pid: u32) -> Result<u32> {
+    let status = std::fs::read_to_string(format!("/proc/{peer_pid}/status")).map_err(|e| {
+        NonoError::SandboxInit(format!("Failed to read status for peer pid {peer_pid}: {e}"))
+    })?;
+    let ppid = status
+        .lines()
+        .find_map(|line| line.strip_prefix("PPid:\t"))
+        .ok_or_else(|| {
+            NonoError::SandboxInit(format!("Missing parent pid for peer pid {peer_pid}"))
+        })?;
+    ppid.parse::<u32>().map_err(|e| {
+        NonoError::SandboxInit(format!(
+            "Failed to parse parent pid for peer pid {peer_pid}: {e}"
+        ))
+    })
+}
+
+#[cfg(target_os = "macos")]
+fn peer_parent_pid(peer_pid: u32) -> Result<u32> {
+    const PROC_PIDTBSDINFO: libc::c_int = 3;
+    const PROC_BSD_INFO_SIZE: usize = 136;
+
+    #[repr(C)]
+    struct ProcBsdInfo {
+        pbi_flags: u32,
+        pbi_status: u32,
+        pbi_xstatus: u32,
+        pbi_pid: u32,
+        pbi_ppid: u32,
+        pbi_uid: u32,
+        pbi_gid: u32,
+        pbi_ruid: u32,
+        pbi_rgid: u32,
+        pbi_svuid: u32,
+        pbi_svgid: u32,
+        _reserved: u32,
+        pbi_comm: [u8; 16],
+        pbi_name: [u8; 32],
+        pbi_nfiles: u32,
+        pbi_pgid: u32,
+        pbi_pjobc: u32,
+        e_tdev: u32,
+        e_tpgid: u32,
+        pbi_nice: i32,
+        pbi_start_tvsec: u64,
+        pbi_start_tvusec: u64,
+    }
+
+    const _: [(); PROC_BSD_INFO_SIZE] = [(); std::mem::size_of::<ProcBsdInfo>()];
+
+    let mut info: ProcBsdInfo = unsafe { std::mem::zeroed() };
+    let ret = unsafe {
+        libc::proc_pidinfo(
+            peer_pid as libc::c_int,
+            PROC_PIDTBSDINFO,
+            0,
+            &mut info as *mut ProcBsdInfo as *mut libc::c_void,
+            PROC_BSD_INFO_SIZE as libc::c_int,
+        )
+    };
+    if ret != PROC_BSD_INFO_SIZE as libc::c_int {
+        return Err(NonoError::SandboxInit(format!(
+            "Failed to read parent pid for peer pid {}: {}",
+            peer_pid,
+            std::io::Error::last_os_error()
+        )));
+    }
+    Ok(info.pbi_ppid)
+}
+
+#[cfg(not(any(target_os = "linux", target_os = "macos")))]
+fn peer_parent_pid(_peer_pid: u32) -> Result<u32> {
+    Err(NonoError::UnsupportedPlatform(
+        "Peer parent lookup not supported on this platform".to_string(),
+    ))
+}
+
 #[doc(hidden)]
 #[cfg(target_os = "linux")]
 pub fn peer_in_same_user_namespace(peer_pid: u32) -> Result<bool> {
```