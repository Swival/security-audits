# Malicious Server Controls Local Download Destination

## Classification

Injection, medium severity.

## Affected Locations

`sftp.c:1499`

## Summary

A malicious SFTP server can control the local destination of an implicit download when the user opens a relative remote path without specifying a local destination. The vulnerable path builds an internal `get` command string using a server-controlled current directory without quoting, then reparses it. Whitespace and `#` in the server-controlled path alter parsed operands, causing attacker-selected data to overwrite an unintended local file under the client user’s privileges.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- User invokes `sftp` with a relative remote path, for example `sftp evilhost:somefile`.
- User does not provide an explicit local destination.
- The SFTP server is malicious or compromised.
- The malicious server controls the value returned for the remote current directory via `sftp_realpath(conn, ".")`.

## Proof

`interactive_loop()` obtains `remote_path` from `sftp_realpath(conn, ".")`, then converts the user-supplied relative `file1` into `dir` using `sftp_make_absolute(dir, remote_path)`.

In the non-directory case, the vulnerable code generated an internal command:

```c
snprintf(cmd, sizeof cmd, "get%s %s%s%s",
    global_aflag ? " -a" : "", dir,
    file2 == NULL ? "" : " ",
    file2 == NULL ? "" : file2);
err = parse_dispatch_command(conn, cmd, &remote_path, startdir, 1, 0);
```

Because `dir` contains server-controlled `remote_path` and is not quoted, `parse_dispatch_command()` reparses it through `parse_args()` and `makeargv()`.

`parse_args()` assigns the second parsed `get` operand to `path2`. `process_get()` then passes `path2` to `sftp_download()` as the local destination. The download path ultimately opens the destination with `O_WRONLY | O_CREAT | O_TRUNC`.

Concrete trigger:

```text
server cwd: /srv/payload /home/victim/.ssh/authorized_keys #
user command: sftp evilhost:somefile
generated command: get /srv/payload /home/victim/.ssh/authorized_keys #/somefile
effective parse: get /srv/payload /home/victim/.ssh/authorized_keys
```

The attacker-controlled remote data is written to `/home/victim/.ssh/authorized_keys`.

## Why This Is A Real Bug

The server-controlled current directory crosses a command-string boundary and is interpreted as client command syntax. Whitespace splits the path into separate operands, and `#` is honored as a comment by `makeargv()`, allowing the server to suppress the appended user path and choose an exact local destination. This produces a practical local file overwrite with the privileges of the `sftp` client user.

## Fix Requirement

Do not construct and reparse an internal `get` command from server-controlled path data. The implementation must either call the transfer routine directly with structured arguments or correctly quote/escape every command operand before reparsing.

## Patch Rationale

The patch removes the vulnerable command-string construction in the implicit download path and calls `process_get()` directly:

```c
err = process_get(conn, dir, file2, remote_path, 0, 0,
    global_aflag, 0);
```

This preserves the intended behavior while keeping the remote source path and optional local destination as separate structured parameters. Server-controlled whitespace and comment characters remain path data and can no longer be reinterpreted as command syntax.

## Residual Risk

None

## Patch

`006-malicious-server-controls-local-download-destination.patch`

```diff
diff --git a/sftp.c b/sftp.c
index 38abe4f..a01247d 100644
--- a/sftp.c
+++ b/sftp.c
@@ -2267,13 +2267,8 @@ interactive_loop(struct sftp_conn *conn, char *file1, char *file2)
 				return (-1);
 			}
 		} else {
-			/* XXX this is wrong wrt quoting */
-			snprintf(cmd, sizeof cmd, "get%s %s%s%s",
-			    global_aflag ? " -a" : "", dir,
-			    file2 == NULL ? "" : " ",
-			    file2 == NULL ? "" : file2);
-			err = parse_dispatch_command(conn, cmd,
-			    &remote_path, startdir, 1, 0);
+			err = process_get(conn, dir, file2, remote_path, 0, 0,
+			    global_aflag, 0);
 			free(dir);
 			free(startdir);
 			free(remote_path);
```