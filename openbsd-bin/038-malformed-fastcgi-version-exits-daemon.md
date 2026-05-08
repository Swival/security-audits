# Malformed FastCGI Version Exits Daemon

## Classification

Denial of service, high severity, certain confidence.

## Affected Locations

`usr.sbin/slowcgi/slowcgi.c:829`

## Summary

A local process that can connect to the configured `slowcgi` Unix socket can terminate the `slowcgi` daemon by sending a malformed FastCGI record whose header `version` field is not `1`.

`parse_record()` validates record completeness, then treats a non-`1` FastCGI version as a daemon-fatal error via `lerrx(1, "wrong version")`. Both logger backends for `errx` terminate the process with `exit(ecode)`, so one malformed client record stops CGI handling until restart.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

An attacker can connect to the `slowcgi` Unix socket, for example from a local process with access to the socket path and permissions.

## Proof

The issue was reproduced.

Reachability is direct:

- `slowcgi_accept()` accepts a client from the configured Unix socket.
- It registers `slowcgi_request()` for reads on the accepted socket.
- `slowcgi_request()` reads attacker-controlled bytes into `c->buf`.
- `slowcgi_request()` calls `parse_record(c->buf + c->buf_pos, c->buf_len, c)`.
- `parse_record()` interprets the buffer as a FastCGI record header after only length/completeness checks.

A minimal malformed record is sufficient:

- 8-byte FastCGI header.
- `version != 1`.
- `content_len = 0`.
- `padding_len = 0`.

That record passes the completeness check:

```c
if (n < sizeof(struct fcgi_record_header) + ntohs(h->content_len)
    + h->padding_len)
	return (0);
```

It then reaches the fatal path:

```c
if (h->version != 1)
	lerrx(1, "wrong version");
```

`lerrx()` dispatches to the active logger’s `errx` implementation. Both console and syslog implementations are process-fatal: the syslog backend calls `exit(ecode)`, and the console backend is `errx`, which also exits.

## Why This Is A Real Bug

The malformed FastCGI version is attacker-controlled input from a connected socket client, not an internal invariant violation.

Rejecting a bad client record should affect only that client connection. Instead, the code calls a daemon-fatal error path, terminating the entire `slowcgi` process and denying CGI service to all clients.

The impact is security-relevant because a single local socket client can stop CGI handling until the service is restarted.

## Fix Requirement

Reject malformed FastCGI versions as per-request protocol errors:

- Log a non-fatal warning.
- Clean up the offending request with `cleanup_request(c)`.
- Prevent the caller from continuing to access the freed request object.
- Do not terminate the daemon.

## Patch Rationale

The patch replaces the daemon-fatal `lerrx(1, "wrong version")` with per-request cleanup:

```c
if (h->version != 1) {
	lwarnx("wrong version");
	cleanup_request(c);
	return ((size_t)-1);
}
```

Because `cleanup_request(c)` frees the request object, `slowcgi_request()` is updated to recognize the sentinel return value and return immediately:

```c
parsed = parse_record(c->buf + c->buf_pos, c->buf_len, c);
if (parsed == (size_t)-1)
	return;
```

This preserves existing parsing behavior for incomplete and valid records while making malformed-version handling non-fatal to the daemon.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/slowcgi/slowcgi.c b/usr.sbin/slowcgi/slowcgi.c
index 9a0f8b5..d089eb1 100644
--- a/usr.sbin/slowcgi/slowcgi.c
+++ b/usr.sbin/slowcgi/slowcgi.c
@@ -660,6 +660,8 @@ slowcgi_request(int fd, short events, void *arg)
 	 */
 	do {
 		parsed = parse_record(c->buf + c->buf_pos, c->buf_len, c);
+		if (parsed == (size_t)-1)
+			return;
 		c->buf_pos += parsed;
 		c->buf_len -= parsed;
 	} while (parsed > 0 && c->buf_len > 0);
@@ -837,8 +839,11 @@ parse_record(uint8_t *buf, size_t n, struct request *c)
 	    + h->padding_len)
 		return (0);
 
-	if (h->version != 1)
-		lerrx(1, "wrong version");
+	if (h->version != 1) {
+		lwarnx("wrong version");
+		cleanup_request(c);
+		return ((size_t)-1);
+	}
 
 	switch (h->type) {
 	case FCGI_BEGIN_REQUEST:
```