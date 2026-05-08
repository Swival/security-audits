# autoconf message string read lacks payload bounds

## Classification

Out-of-bounds read. Severity: medium. Confidence: certain.

## Affected Locations

`usr.sbin/unwindctl/unwindctl.c:302`

## Summary

`unwindctl autoconf` accepted `IMSG_CTL_AUTOCONF_RESOLVER_INFO` payloads from its control socket and treated `imsg->data` as a complete `struct ctl_forwarder_info` without validating the imsg payload length or the termination of `cfi->ip`.

Because `cfi->ip` is a fixed-size character array, a malicious control socket peer could send a resolver-info message whose `ip` field contains no NUL byte. The client then called `strlen(cfi->ip)` and later appended it with `strlcat`, causing libc to read beyond the received imsg payload.

## Provenance

Reported and reproduced from Swival Security Scanner output: https://swival.dev

## Preconditions

- The user runs `unwindctl autoconf`.
- The user selects or is induced to use an attacker-controlled UNIX control socket via `-s`.
- The malicious socket peer replies with `IMSG_CTL_AUTOCONF_RESOLVER_INFO`.
- The reply payload contains a non-NUL-terminated `ip` field.

## Proof

`unwindctl` connects to a user-selectable UNIX socket through `-s`, sends `IMSG_CTL_AUTOCONF`, and dispatches replies to `show_autoconf_msg`.

For `IMSG_CTL_AUTOCONF_RESOLVER_INFO`, the vulnerable code did:

```c
cfi = imsg->data;
...
if (line_len + 1 + strlen(cfi->ip) > sizeof(fwd_line)) {
...
}
...
line_len = strlcat(fwd_line, cfi->ip, sizeof(fwd_line));
```

No check proved that:

- `IMSG_DATA_SIZE(*imsg)` was exactly `sizeof(struct ctl_forwarder_info)`.
- `cfi->ip` contained a NUL byte within its fixed `char ip[INET6_ADDRSTRLEN]` storage.

A malicious peer can therefore send a syntactically valid imsg with an unterminated `ip` array. `strlen(cfi->ip)` scans past the end of the imsg data allocation, producing an out-of-bounds read and practical client crash/DoS.

## Why This Is A Real Bug

The real daemon normally sends zeroed, well-formed `struct ctl_forwarder_info` values, but `unwindctl` does not only talk to the real daemon. Its `-s` option allows a user-selected UNIX socket path.

That makes the imsg peer attacker-controlled under the stated precondition. The client must therefore validate hostile payload length and string termination before using C string APIs. The vulnerable code did neither before calling `strlen` and `strlcat`.

## Fix Requirement

- Validate that the received imsg payload size matches `sizeof(struct ctl_forwarder_info)`.
- Validate that `cfi->ip` is NUL-terminated within `sizeof(cfi->ip)`.
- Use the bounded length result for layout calculations instead of unbounded `strlen`.

## Patch Rationale

The patch adds `ip_len` and rejects malformed resolver-info messages before any string operation:

```c
if (IMSG_DATA_SIZE(*imsg) != sizeof(*cfi))
	break;
cfi = imsg->data;
ip_len = strnlen(cfi->ip, sizeof(cfi->ip));
if (ip_len == sizeof(cfi->ip))
	break;
```

This ensures the payload is structurally complete and that `cfi->ip` is a valid bounded C string inside the received struct. The line wrapping calculation then uses `ip_len` instead of `strlen(cfi->ip)`, removing the unbounded read path.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/unwindctl/unwindctl.c b/usr.sbin/unwindctl/unwindctl.c
index 2735c33..b21f11b 100644
--- a/usr.sbin/unwindctl/unwindctl.c
+++ b/usr.sbin/unwindctl/unwindctl.c
@@ -280,10 +280,16 @@ show_autoconf_msg(struct imsg *imsg)
 	struct ctl_forwarder_info	*cfi;
 	char				 ifnamebuf[IFNAMSIZ];
 	char				*if_name;
+	size_t				 ip_len;
 
 	switch (imsg->hdr.type) {
 	case IMSG_CTL_AUTOCONF_RESOLVER_INFO:
+		if (IMSG_DATA_SIZE(*imsg) != sizeof(*cfi))
+			break;
 		cfi = imsg->data;
+		ip_len = strnlen(cfi->ip, sizeof(cfi->ip));
+		if (ip_len == sizeof(cfi->ip))
+			break;
 		if (!autoconf_forwarders++)
 			printf("autoconfiguration forwarders:\n");
 		if (cfi->if_index != last_if_index || cfi->src != last_src) {
@@ -300,7 +306,7 @@ show_autoconf_msg(struct imsg *imsg)
 			last_src = cfi->src;
 		}
 
-		if (line_len + 1 + strlen(cfi->ip) > sizeof(fwd_line)) {
+		if (line_len + 1 + ip_len > sizeof(fwd_line)) {
 			printf("%s\n", fwd_line);
 			snprintf(fwd_line, sizeof(fwd_line), "%*s", label_len,
 			    " ");
```