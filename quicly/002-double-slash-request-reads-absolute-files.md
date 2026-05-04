# Double-Slash Request Reads Absolute Files

## Classification

High severity information disclosure.

## Affected Locations

`src/cli.c:176`  
`src/cli.c:343`  
`src/cli.c:360`  
`src/cli.c:250`

## Summary

The CLI server accepted request paths beginning with `//`. Because validated paths are later passed to `send_file` as `path + 1`, a request such as `GET //etc/passwd HTTP/1.1\r\n\r\n` becomes `/etc/passwd` at the file-open site. This lets an unauthenticated QUIC client read absolute files that are readable by the server process.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The CLI is running in server mode, and the targeted absolute file is readable by the server process.

## Proof

An unauthenticated QUIC client can open a stream and send:

```http
GET //etc/passwd HTTP/1.1\r\n\r\n
```

Execution path:

- `server_on_receive` parses attacker-controlled stream data with `parse_request` at `src/cli.c:343`.
- `validate_path` at `src/cli.c:176` only required `path[0] == '/'` and rejected paths containing `/.`.
- The path `//etc/passwd` satisfies both checks.
- `server_on_receive` calls `send_file(stream, is_http1, path + 1, "text/plain")` at `src/cli.c:360`.
- For `//etc/passwd`, `path + 1` is `/etc/passwd`.
- `send_file` calls `open(fn, O_RDONLY)` at `src/cli.c:250`, opening the absolute file with server process privileges and returning its contents on the stream.

The reproducer confirmed this behavior.

## Why This Is A Real Bug

The validation and consumption logic disagree on path semantics. `validate_path` treats `//etc/passwd` as an acceptable request path because it starts with `/` and does not contain `/.`, while `send_file(path + 1)` converts it into an absolute filesystem path. This crosses the intended boundary from serving relative files under the process working directory to serving arbitrary readable absolute files.

## Fix Requirement

Reject request paths whose second byte is `/`, or otherwise normalize/canonicalize the request path before applying `path + 1` and opening files.

## Patch Rationale

The patch rejects double-slash paths directly in `validate_path`, before the path reaches `send_file`. This preserves the existing validation model while closing the exact mismatch that allowed `path + 1` to become an absolute path.

## Residual Risk

None

## Patch

```diff
diff --git a/src/cli.c b/src/cli.c
index f55ea83..9f78013 100644
--- a/src/cli.c
+++ b/src/cli.c
@@ -175,7 +175,7 @@ static void dump_stats(FILE *fp, quicly_conn_t *conn)
 
 static int validate_path(const char *path)
 {
-    if (path[0] != '/')
+    if (path[0] != '/' || path[1] == '/')
         return 0;
     /* TODO avoid false positives on the client-side */
     if (strstr(path, "/.") != NULL)
```