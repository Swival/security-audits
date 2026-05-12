# proxy seccomp fallback allows untrapped UDP egress

## Classification

High severity policy bypass.

## Affected Locations

- `crates/nono/src/sandbox/linux.rs:1112`
- `crates/nono/src/sandbox/linux.rs:1734`
- `crates/nono/src/sandbox/linux.rs:1769`
- `crates/nono/src/sandbox/linux.rs:1783`
- `crates/nono/src/sandbox/linux.rs:1797`
- `crates/nono/src/sandbox/linux.rs:1853`
- `crates/nono-cli/src/exec_strategy/supervisor_linux.rs:612`

## Summary

On kernels whose Landlock ABI lacks `AccessNet`, proxy-only network policy falls back to a seccomp user-notification filter. That filter allowed `socket(AF_INET|AF_INET6, SOCK_DGRAM, 0)` and did not trap `sendto` or `sendmsg`, so a sandboxed child could send arbitrary UDP packets without supervisor policy checks.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Proxy-only network mode is requested.
- Kernel Landlock ABI is pre-V4, so `AccessNet::from_all(target_abi)` is empty.
- The sandbox selects `SeccompNetFallback::ProxyOnly`.
- A sandboxed child can issue raw socket syscalls.

## Proof

`apply_with_abi` selects `SeccompNetFallback::ProxyOnly` when network filtering is needed but Landlock `AccessNet` is unavailable.

The proxy seccomp fallback only routed `connect` and `bind` to `SECCOMP_RET_USER_NOTIF`, denied `io_uring_setup`, constrained `socketpair` to `AF_UNIX`, and allowed `socket` for `AF_UNIX`, `AF_INET`, and `AF_INET6`.

Because the original `socket` check inspected only `args[0]` address family and not `args[1]` socket type, this sequence succeeded:

```c
int fd = socket(AF_INET, SOCK_DGRAM, 0);
sendto(fd, data, len, 0, (struct sockaddr *)&remote, sizeof(remote));
```

`sendto`/`sendmsg` were not trapped, and the supervisor only decided `SYS_CONNECT` and `SYS_BIND`, so UDP egress bypassed the proxy-only localhost/proxy-port policy.

## Why This Is A Real Bug

Proxy-only mode is intended to restrict network egress to approved TCP proxy connectivity and configured bind ports. UDP sockets do not require `connect(2)` before transmission; `sendto(2)` can specify the remote address directly. Since the seccomp filter allowed internet-family datagram sockets and did not mediate UDP send syscalls, the sandboxed child gained attacker-controlled UDP egress outside the proxy policy.

## Fix Requirement

The fallback must fail closed for unmediated UDP egress. Acceptable fixes include:

- Deny `AF_INET`/`AF_INET6` datagram sockets in the proxy seccomp fallback.
- Or trap and authorize UDP send syscalls.
- Preserve existing allowed `AF_UNIX` behavior and TCP `connect`/`bind` supervisor mediation.

## Patch Rationale

The patch restricts proxy fallback `socket()` creation instead of adding UDP send mediation.

It adds BPF support for reading `socket` argument 1 and masking Linux socket flags:

- `SECCOMP_DATA_ARG1_OFFSET`
- `SOCK_TYPE_MASK`
- `BPF_ALU`
- `BPF_AND`

The proxy filter now allows:

- `AF_UNIX` sockets as before.
- `AF_INET`/`AF_INET6` sockets only when `(type & SOCK_TYPE_MASK) == SOCK_STREAM`.
- `AF_UNIX` socketpairs as before.
- `connect` and `bind` through user notification as before.
- `io_uring_setup` denied as before.

This blocks `SOCK_DGRAM` IPv4/IPv6 sockets before any `sendto` path exists, eliminating the reproduced UDP egress bypass while preserving the intended TCP proxy flow.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono/src/sandbox/linux.rs b/crates/nono/src/sandbox/linux.rs
index 6bc5275..1a260d2 100644
--- a/crates/nono/src/sandbox/linux.rs
+++ b/crates/nono/src/sandbox/linux.rs
@@ -792,6 +792,8 @@ const BPF_W: u16 = 0x00;
 const BPF_ABS: u16 = 0x20;
 const BPF_JMP: u16 = 0x05;
 const BPF_JEQ: u16 = 0x10;
+const BPF_ALU: u16 = 0x04;
+const BPF_AND: u16 = 0x50;
 const BPF_K: u16 = 0x00;
 const BPF_RET: u16 = 0x06;
 
@@ -872,6 +874,8 @@ pub fn validate_openat2_size(how_size: usize) -> bool {
 // Offset of `nr` field in seccomp_data (used by BPF)
 const SECCOMP_DATA_NR_OFFSET: u32 = 0;
 const SECCOMP_DATA_ARG0_OFFSET: u32 = 16;
+const SECCOMP_DATA_ARG1_OFFSET: u32 = 24;
+const SOCK_TYPE_MASK: u32 = 0xf;
 
 /// A single BPF instruction.
 #[repr(C)]
@@ -1662,31 +1666,34 @@ pub fn seccomp_network_fallback_mode(caps: &CapabilitySet) -> SeccompNetFallback
 /// failed AF_UNIX bind (regression on Landlock V2 kernels where this
 /// fallback fires). The supervisor is the sole arbiter now.
 ///
-/// `socket()` is allowed only for `AF_UNIX`, `AF_INET`, `AF_INET6`.
+/// `socket()` is allowed for `AF_UNIX`, and for TCP-only `AF_INET`/`AF_INET6`.
 /// `socketpair()` is allowed only for `AF_UNIX`.
 /// `io_uring_setup()` is denied.
 ///
-/// Instruction layout (19 instructions, jt = jump offset from next insn):
+/// Instruction layout (22 instructions, jt = jump offset from next insn):
 /// ```text
 ///  0: ld  [nr]
 ///  1: jeq SYS_SOCKET     jt=+6  (-> 8: load socket family)
-///  2: jeq SYS_CONNECT    jt=+13 (-> 16: notify)
-///  3: jeq SYS_BIND       jt=+13 (-> 17: notify)
-///  4: jeq SYS_SOCKETPAIR jt=+8  (-> 13: load socketpair family)
+///  2: jeq SYS_CONNECT    jt=+16 (-> 19: notify)
+///  3: jeq SYS_BIND       jt=+16 (-> 20: notify)
+///  4: jeq SYS_SOCKETPAIR jt=+11 (-> 16: load socketpair family)
 ///  5: jeq SYS_IO_URING   jt=+1  (-> 7: errno)
 ///  6: ret ALLOW
 ///  7: ret ERRNO(EACCES)
 ///  8: ld  [args[0]]             ; socket() family
-///  9: jeq AF_UNIX  jt=+8 (-> 18: allow)
-/// 10: jeq AF_INET  jt=+7 (-> 18: allow)
-/// 11: jeq AF_INET6 jt=+6 (-> 18: allow)
-/// 12: ret ERRNO(EACCES)         ; bad socket family
-/// 13: ld  [args[0]]             ; socketpair() family
-/// 14: jeq AF_UNIX  jt=+3 (-> 18: allow)
-/// 15: ret ERRNO(EACCES)         ; bad socketpair family
-/// 16: ret USER_NOTIF            ; connect
-/// 17: ret USER_NOTIF            ; bind
-/// 18: ret ALLOW                 ; allowed socket/socketpair
+///  9: jeq AF_UNIX  jt=+11 (-> 21: allow)
+/// 10: jeq AF_INET  jt=+1  (-> 12: load socket type)
+/// 11: jeq AF_INET6 jt=+0 jf=+3 (-> 12: load socket type, else 15: errno)
+/// 12: ld  [args[1]]             ; socket() type
+/// 13: and SOCK_TYPE_MASK
+/// 14: jeq SOCK_STREAM jt=+6 (-> 21: allow)
+/// 15: ret ERRNO(EACCES)         ; bad socket family/type
+/// 16: ld  [args[0]]             ; socketpair() family
+/// 17: jeq AF_UNIX  jt=+3 (-> 21: allow)
+/// 18: ret ERRNO(EACCES)         ; bad socketpair family
+/// 19: ret USER_NOTIF            ; connect
+/// 20: ret USER_NOTIF            ; bind
+/// 21: ret ALLOW                 ; allowed socket/socketpair
 /// ```
 fn build_seccomp_proxy_filter(_has_bind_ports: bool) -> Vec<SockFilterInsn> {
     let errno_ret = SECCOMP_RET_ERRNO | (libc::EACCES as u32);
@@ -1705,23 +1712,26 @@ fn build_seccomp_proxy_filter(_has_bind_ports: bool) -> Vec<SockFilterInsn> {
     // Target instruction index table (jt/jf are offsets from next insn):
     //  0: ld [nr]
     //  1: jeq SOCKET     jt=6  -> insn 8
-    //  2: jeq CONNECT    jt=13 -> insn 16
-    //  3: jeq BIND       jt=13 -> insn 17
-    //  4: jeq SOCKETPAIR jt=8  -> insn 13
+    //  2: jeq CONNECT    jt=16 -> insn 19
+    //  3: jeq BIND       jt=16 -> insn 20
+    //  4: jeq SOCKETPAIR jt=11 -> insn 16
     //  5: jeq IO_URING   jt=1  -> insn 7
     //  6: ret ALLOW
     //  7: ret ERRNO
     //  8: ld [args[0]]
-    //  9: jeq AF_UNIX    jt=8  -> insn 18
-    // 10: jeq AF_INET    jt=7  -> insn 18
-    // 11: jeq AF_INET6   jt=6  -> insn 18
-    // 12: ret ERRNO            (bad socket family)
-    // 13: ld [args[0]]
-    // 14: jeq AF_UNIX    jt=3  -> insn 18
-    // 15: ret ERRNO            (bad socketpair family)
-    // 16: ret USER_NOTIF       (connect)
-    // 17: ret bind_action      (bind)
-    // 18: ret ALLOW            (good socket/socketpair)
+    //  9: jeq AF_UNIX    jt=11 -> insn 21
+    // 10: jeq AF_INET    jt=1  -> insn 12
+    // 11: jeq AF_INET6   jt=0 jf=3 -> insn 12, else insn 15
+    // 12: ld [args[1]]
+    // 13: and SOCK_TYPE_MASK
+    // 14: jeq SOCK_STREAM jt=6 -> insn 21
+    // 15: ret ERRNO            (bad socket family/type)
+    // 16: ld [args[0]]
+    // 17: jeq AF_UNIX    jt=3  -> insn 21
+    // 18: ret ERRNO            (bad socketpair family)
+    // 19: ret USER_NOTIF       (connect)
+    // 20: ret bind_action      (bind)
+    // 21: ret ALLOW            (good socket/socketpair)
 
     vec![
         // 0: ld [nr]
@@ -1738,24 +1748,24 @@ fn build_seccomp_proxy_filter(_has_bind_ports: bool) -> Vec<SockFilterInsn> {
             jf: 0,
             k: SYS_SOCKET as u32,
         },
-        // 2: jeq SYS_CONNECT -> 16 (jt = 16-2-1 = 13)
+        // 2: jeq SYS_CONNECT -> 19 (jt = 19-2-1 = 16)
         SockFilterInsn {
             code: BPF_JMP | BPF_JEQ | BPF_K,
-            jt: 13,
+            jt: 16,
             jf: 0,
             k: SYS_CONNECT as u32,
         },
-        // 3: jeq SYS_BIND -> 17 (jt = 17-3-1 = 13)
+        // 3: jeq SYS_BIND -> 20 (jt = 20-3-1 = 16)
         SockFilterInsn {
             code: BPF_JMP | BPF_JEQ | BPF_K,
-            jt: 13,
+            jt: 16,
             jf: 0,
             k: SYS_BIND as u32,
         },
-        // 4: jeq SYS_SOCKETPAIR -> 13 (jt = 13-4-1 = 8)
+        // 4: jeq SYS_SOCKETPAIR -> 16 (jt = 16-4-1 = 11)
         SockFilterInsn {
             code: BPF_JMP | BPF_JEQ | BPF_K,
-            jt: 8,
+            jt: 11,
             jf: 0,
             k: SYS_SOCKETPAIR as u32,
         },
@@ -1787,70 +1797,91 @@ fn build_seccomp_proxy_filter(_has_bind_ports: bool) -> Vec<SockFilterInsn> {
             jf: 0,
             k: SECCOMP_DATA_ARG0_OFFSET,
         },
-        // 9: jeq AF_UNIX -> 18 (jt = 18-9-1 = 8)
+        // 9: jeq AF_UNIX -> 21 (jt = 21-9-1 = 11)
         SockFilterInsn {
             code: BPF_JMP | BPF_JEQ | BPF_K,
-            jt: 8,
+            jt: 11,
             jf: 0,
             k: libc::AF_UNIX as u32,
         },
-        // 10: jeq AF_INET -> 18 (jt = 18-10-1 = 7)
+        // 10: jeq AF_INET -> 12 (jt = 12-10-1 = 1)
         SockFilterInsn {
             code: BPF_JMP | BPF_JEQ | BPF_K,
-            jt: 7,
+            jt: 1,
             jf: 0,
             k: libc::AF_INET as u32,
         },
-        // 11: jeq AF_INET6 -> 18 (jt = 18-11-1 = 6)
+        // 11: jeq AF_INET6 -> 12, else 15 (jt = 0, jf = 15-11-1 = 3)
+        SockFilterInsn {
+            code: BPF_JMP | BPF_JEQ | BPF_K,
+            jt: 0,
+            jf: 3,
+            k: libc::AF_INET6 as u32,
+        },
+        // 12: ld [args[1]] — socket() type
+        SockFilterInsn {
+            code: BPF_LD | BPF_W | BPF_ABS,
+            jt: 0,
+            jf: 0,
+            k: SECCOMP_DATA_ARG1_OFFSET,
+        },
+        // 13: and SOCK_TYPE_MASK
+        SockFilterInsn {
+            code: BPF_ALU | BPF_AND | BPF_K,
+            jt: 0,
+            jf: 0,
+            k: SOCK_TYPE_MASK,
+        },
+        // 14: jeq SOCK_STREAM -> 21 (jt = 21-14-1 = 6)
         SockFilterInsn {
             code: BPF_JMP | BPF_JEQ | BPF_K,
             jt: 6,
             jf: 0,
-            k: libc::AF_INET6 as u32,
+            k: libc::SOCK_STREAM as u32,
         },
-        // 12: ret ERRNO(EACCES) — bad socket family
+        // 15: ret ERRNO(EACCES) — bad socket family/type
         SockFilterInsn {
             code: BPF_RET | BPF_K,
             jt: 0,
             jf: 0,
             k: errno_ret,
         },
-        // 13: ld [args[0]] — socketpair() family
+        // 16: ld [args[0]] — socketpair() family
         SockFilterInsn {
             code: BPF_LD | BPF_W | BPF_ABS,
             jt: 0,
             jf: 0,
             k: SECCOMP_DATA_ARG0_OFFSET,
         },
-        // 14: jeq AF_UNIX -> 18 (jt = 18-14-1 = 3)
+        // 17: jeq AF_UNIX -> 21 (jt = 21-17-1 = 3)
         SockFilterInsn {
             code: BPF_JMP | BPF_JEQ | BPF_K,
             jt: 3,
             jf: 0,
             k: libc::AF_UNIX as u32,
         },
-        // 15: ret ERRNO(EACCES) — bad socketpair family
+        // 18: ret ERRNO(EACCES) — bad socketpair family
         SockFilterInsn {
             code: BPF_RET | BPF_K,
             jt: 0,
             jf: 0,
             k: errno_ret,
         },
-        // 16: ret USER_NOTIF — connect()
+        // 19: ret USER_NOTIF — connect()
         SockFilterInsn {
             code: BPF_RET | BPF_K,
             jt: 0,
             jf: 0,
             k: SECCOMP_RET_USER_NOTIF,
         },
-        // 17: ret bind_action — bind()
+        // 20: ret bind_action — bind()
         SockFilterInsn {
             code: BPF_RET | BPF_K,
             jt: 0,
             jf: 0,
             k: bind_action,
         },
-        // 18: ret ALLOW — good socket/socketpair family
+        // 21: ret ALLOW — good socket/socketpair family/type
         SockFilterInsn {
             code: BPF_RET | BPF_K,
             jt: 0,
@@ -2761,20 +2792,20 @@ mod tests {
     #[test]
     fn test_build_seccomp_proxy_filter_with_bind() {
         let filter = build_seccomp_proxy_filter(true);
-        // 19 instructions
-        assert_eq!(filter.len(), 19);
+        // 22 instructions
+        assert_eq!(filter.len(), 22);
 
         // Instruction 0 should be ld [nr]
         assert_eq!(filter[0].code, BPF_LD | BPF_W | BPF_ABS);
         assert_eq!(filter[0].k, SECCOMP_DATA_NR_OFFSET);
 
-        // Instruction 16 should be USER_NOTIF (connect)
-        assert_eq!(filter[16].code, BPF_RET | BPF_K);
-        assert_eq!(filter[16].k, SECCOMP_RET_USER_NOTIF);
+        // Instruction 19 should be USER_NOTIF (connect)
+        assert_eq!(filter[19].code, BPF_RET | BPF_K);
+        assert_eq!(filter[19].k, SECCOMP_RET_USER_NOTIF);
 
-        // Instruction 17 should be USER_NOTIF (bind; supervisor decides).
-        assert_eq!(filter[17].code, BPF_RET | BPF_K);
-        assert_eq!(filter[17].k, SECCOMP_RET_USER_NOTIF);
+        // Instruction 20 should be USER_NOTIF (bind; supervisor decides).
+        assert_eq!(filter[20].code, BPF_RET | BPF_K);
+        assert_eq!(filter[20].k, SECCOMP_RET_USER_NOTIF);
     }
 
     /// Regression test for the Landlock V2 + `has_bind_ports=false`
@@ -2785,14 +2816,14 @@ mod tests {
     #[test]
     fn test_build_seccomp_proxy_filter_without_bind() {
         let filter = build_seccomp_proxy_filter(false);
-        assert_eq!(filter.len(), 19);
+        assert_eq!(filter.len(), 22);
 
-        // Instruction 17 (bind) must ALSO route to USER_NOTIF — the
+        // Instruction 20 (bind) must ALSO route to USER_NOTIF — the
         // supervisor is the sole gate. This is the fix: previously this
         // emitted ERRNO, which skipped the supervisor entirely.
-        assert_eq!(filter[17].code, BPF_RET | BPF_K);
+        assert_eq!(filter[20].code, BPF_RET | BPF_K);
         assert_eq!(
-            filter[17].k, SECCOMP_RET_USER_NOTIF,
+            filter[20].k, SECCOMP_RET_USER_NOTIF,
             "bind must route to USER_NOTIF regardless of has_bind_ports so \
              the supervisor can permit AF_UNIX pathname bind (#685)"
         );
```