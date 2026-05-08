# Write-Capable Open Bypasses Request Restrictions

## Classification

Policy bypass, medium severity. Confidence: certain.

## Affected Locations

`usr.bin/ssh/sftp-server.c:120`

## Summary

`SSH2_FXP_OPEN` is permitted or denied using only the handler name `open`. The requested open flags are parsed later inside `process_open()`, allowing an authenticated SFTP client to create or truncate files with `WRITE`, `CREAT`, or `TRUNC` flags when policy permits `open` but denies write-like requests.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The SFTP request policy permits `open`.
- The same policy denies write-like request names such as `write`.
- The server is not running in global read-only mode, or request restrictions are relied on independently.
- Filesystem permissions allow the target create, truncate, or write-capable open operation.

## Proof

`process()` dispatches non-extended packets by locating the handler for the packet type and calling `request_permitted(&handlers[i])` before invoking the handler.

For `SSH2_FXP_OPEN`, the handler table entry is:

```c
{ "open", NULL, SSH2_FXP_OPEN, process_open, 0 },
```

This means `request_permitted()` checks allow/deny policy against the name `open`, with `does_write` set to `0`.

After that check succeeds, `process_open()` parses attacker-controlled `pflags`, converts them with `flags_from_portable()`, and calls:

```c
fd = open(name, flags, mode);
```

`flags_from_portable()` maps SFTP flags to native write-capable flags including `O_WRONLY`, `O_CREAT`, and `O_TRUNC`. The only existing flag-based protection is the separate `readonly` check in `process_open()`.

An authenticated restricted client can therefore send `SSH2_FXP_OPEN` with `SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC`. If `open` is allowed but `write` is denied, the request passes policy and reaches `open(2)`, causing the server to create or truncate the file before any denied `SSH2_FXP_WRITE` request is needed.

## Why This Is A Real Bug

The request restriction mechanism is intended to enforce allowed and denied SFTP operations by request semantics. A write-capable `OPEN` has filesystem side effects equivalent to write permission because `O_CREAT` can create a file and `O_TRUNC` can destroy existing file contents.

The current implementation authorizes the request based only on the literal request name `open`, not on whether the supplied flags make the operation write-capable. This creates a mismatch between policy intent and enforcement.

## Fix Requirement

Write-capable `SSH2_FXP_OPEN` requests must be treated as write requests for request permission checks. If an `open` includes a non-read-only access mode, `O_CREAT`, or `O_TRUNC`, it must also satisfy the same policy gate used for `write`.

## Patch Rationale

The patch adds a local synthetic `write` handler inside `process_open()` and calls `request_permitted()` against it whenever the converted open flags are write-capable:

```c
((flags & O_ACCMODE) != O_RDONLY || (flags & (O_CREAT|O_TRUNC)) != 0)
```

This preserves normal read-only `open` behavior while making create, truncate, and write-capable opens subject to the configured write restriction policy.

The existing read-only mode check remains in place, so global `-R` behavior is preserved.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ssh/sftp-server.c b/usr.bin/ssh/sftp-server.c
index 33062da..5c9c54c 100644
--- a/usr.bin/ssh/sftp-server.c
+++ b/usr.bin/ssh/sftp-server.c
@@ -731,6 +731,8 @@ process_init(void)
 static void
 process_open(uint32_t id)
 {
+	static const struct sftp_handler write_handler =
+	    { "write", NULL, SSH2_FXP_WRITE, process_write, 1 };
 	uint32_t pflags;
 	Attrib a;
 	char *name;
@@ -746,7 +748,11 @@ process_open(uint32_t id)
 	mode = (a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a.perm : 0666;
 	logit("open \"%s\" flags %s mode 0%o",
 	    name, string_from_portable(pflags), mode);
-	if (readonly &&
+	if (((flags & O_ACCMODE) != O_RDONLY ||
+	    (flags & (O_CREAT|O_TRUNC)) != 0) &&
+	    !request_permitted(&write_handler)) {
+		status = SSH2_FX_PERMISSION_DENIED;
+	} else if (readonly &&
 	    ((flags & O_ACCMODE) != O_RDONLY ||
 	    (flags & (O_CREAT|O_TRUNC)) != 0)) {
 		verbose("Refusing open request in read-only mode");
```