# Invalid FastCGI Version Exits Daemon

## Classification

denial of service, high severity, confidence certain

## Affected Locations

`usr.sbin/bgplgd/slowcgi.c:864`

## Summary

A FastCGI peer with access to the configured Unix socket can send a complete FastCGI record whose `version` field is not `1`. `parse_record()` treats this protocol error as fatal by calling `lerrx(1, "wrong version")`, which exits the daemon process and denies `bgplgd` service to legitimate clients.

## Provenance

Verified from supplied source, reproduced control flow, and patch evidence. Original scanner provenance: [Swival Security Scanner](https://swival.dev).

## Preconditions

An attacker can connect to the configured FastCGI Unix socket.

## Proof

`slowcgi_accept()` accepts a socket and installs `slowcgi_request()` as the read handler at `usr.sbin/bgplgd/slowcgi.c:496`.

`slowcgi_request()` reads attacker-controlled bytes into `c->buf` and calls `parse_record()` directly at `usr.sbin/bgplgd/slowcgi.c:688`.

`parse_record()` first waits until the full FastCGI header, content, and padding are present. Once complete, it checks `h->version`; when `h->version != 1`, it calls `lerrx(1, "wrong version")`.

`lerrx` resolves to a fatal logger path. In daemon mode, `syslog_errx()` calls `exit(ecode)` at `usr.sbin/bgplgd/slowcgi.c:1249`; in console/debug mode, libc `errx` is also process-fatal.

The default socket is documented as a FastCGI Unix socket owned by `www:www` with mode `0660` at `usr.sbin/bgplgd/bgplgd.8:40`, so a malicious peer with that socket access can terminate the daemon.

## Why This Is A Real Bug

The invalid version is attacker-controlled protocol input from a per-connection FastCGI peer. A malformed client record should be rejected at request scope, not handled as an unrecoverable daemon invariant failure. Because the fatal logger exits the whole process, one malformed record from an authorized socket peer causes service-wide denial of service.

## Fix Requirement

Reject invalid-version records by closing only the offending request connection. The daemon must continue serving other existing and future clients.

## Patch Rationale

The patch changes `parse_record()` so an invalid FastCGI version logs a warning with `lwarnx("wrong version")` and returns `(size_t)-1` instead of calling the fatal `lerrx()` path.

`slowcgi_request()` now checks for `(size_t)-1` from `parse_record()` and jumps to its existing `fail` path, which calls `cleanup_request(c)`. This reuses the established per-request cleanup behavior while avoiding daemon exit.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/bgplgd/slowcgi.c b/usr.sbin/bgplgd/slowcgi.c
index 65cc1bd..506adbf 100644
--- a/usr.sbin/bgplgd/slowcgi.c
+++ b/usr.sbin/bgplgd/slowcgi.c
@@ -686,6 +686,8 @@ slowcgi_request(int fd, short events, void *arg)
 	 */
 	do {
 		parsed = parse_record(c->buf + c->buf_pos, c->buf_len, c);
+		if (parsed == (size_t)-1)
+			goto fail;
 		c->buf_pos += parsed;
 		c->buf_len -= parsed;
 	} while (parsed > 0 && c->buf_len > 0);
@@ -845,8 +847,10 @@ parse_record(uint8_t *buf, size_t n, struct request *c)
 	    + h->padding_len)
 		return (0);
 
-	if (h->version != 1)
-		lerrx(1, "wrong version");
+	if (h->version != 1) {
+		lwarnx("wrong version");
+		return ((size_t)-1);
+	}
 
 	switch (h->type) {
 	case FCGI_BEGIN_REQUEST:
```