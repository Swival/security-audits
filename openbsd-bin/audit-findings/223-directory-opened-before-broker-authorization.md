# Directory Opened Before Broker Authorization

## Classification

Information disclosure, low severity.

Confidence: certain.

## Affected Locations

`sbin/isakmpd/monitor.c:841`

## Summary

The privileged isakmpd monitor handled `MONITOR_REQ_READDIR` by calling `opendir()` on an unprivileged-child-controlled path before authorizing that path against the broker policy. This let a compromised child distinguish unauthorized directories that the privileged process could open from nonexistent or unreadable directories, disclosing root-side directory existence/readability outside the intended roots.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

- Attacker can send monitor protocol messages as the unprivileged isakmpd child process.
- Attacker can trigger `MONITOR_REQ_READDIR` with an arbitrary path.

## Proof

`monitor_loop()` dispatches `MONITOR_REQ_READDIR` directly to `m_priv_req_readdir()`.

In `m_priv_req_readdir()`:

- The privileged monitor reads the child-supplied pathname.
- It calls `opendir(path)` before authorizing `path`.
- If `opendir(path)` fails, it returns `-1` and the actual `errno`.
- If `opendir(path)` succeeds, it immediately returns `0`.
- Only later, while iterating entries, it applies `m_priv_local_sanitize_path()` to individual child paths.

The intended policy in `m_priv_local_sanitize_path()` permits only:

- `/var/run/`
- read-only paths under `/etc/isakmpd/`

Therefore, a compromised child can submit paths outside those roots, such as `/root/` versus a nonexistent directory, and learn whether the privileged monitor can open them. The file descriptors for entries remain filtered, but the initial directory open result leaks existence/openability.

## Why This Is A Real Bug

The privileged broker is responsible for enforcing path authorization before performing privileged filesystem operations. Here, the privileged operation `opendir(path)` occurs before authorization.

The response channel exposes the result of that unauthorized operation:

- Success is reported as `0`.
- Failure is reported as `-1` plus `errno`.

That observable difference leaks information about privileged filesystem state outside the broker-approved path set.

## Fix Requirement

Authorize the requested directory path before `opendir()`.

If authorization fails, return `-1` with `EACCES` and do not call `opendir()`.

## Patch Rationale

The patch inserts a call to `m_priv_local_sanitize_path(path, sizeof path, O_RDONLY)` immediately after pathname validation and before computing offsets or calling `opendir()`.

On denial, it returns:

- `ret = -1`
- `serrno = EACCES`

This preserves monitor protocol behavior while ensuring unauthorized paths do not reach `opendir()`. It also avoids leaking whether a denied directory exists or is readable by the privileged process.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/isakmpd/monitor.c b/sbin/isakmpd/monitor.c
index 87b50ab..2a018a9 100644
--- a/sbin/isakmpd/monitor.c
+++ b/sbin/isakmpd/monitor.c
@@ -837,6 +837,14 @@ m_priv_req_readdir(void)
 	if (strlen(path) != len)
 		log_fatal("m_priv_req_readdir: invalid pathname");
 
+	if (m_priv_local_sanitize_path(path, sizeof path, O_RDONLY) != 0) {
+		serrno = EACCES;
+		ret = -1;
+		must_write(&ret, sizeof ret);
+		must_write(&serrno, sizeof serrno);
+		return;
+	}
+
 	off = strlen(path);
 	size = sizeof path - off;
```