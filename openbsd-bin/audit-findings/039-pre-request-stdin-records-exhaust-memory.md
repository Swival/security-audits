# Pre-Request Stdin Records Exhaust Memory

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.sbin/slowcgi/slowcgi.c:791`

## Summary

`slowcgi` accepted `FCGI_STDIN` records before a `FCGI_BEGIN_REQUEST` was processed. Because each accepted stdin record allocated and queued a `struct fcgi_stdin`, a local client with access to the Unix socket could repeatedly send request-id-zero stdin records and exhaust daemon memory before any CGI request was started.

## Provenance

Verified from the provided source, reproduced data, and patch. Originally reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

An attacker can open the `slowcgi` Unix socket and keep connections active.

## Proof

- `slowcgi_accept()` allocates each request with `calloc(1, sizeof(*c))`, leaving `c->id == 0` and `c->request_started == 0`.
- `slowcgi_request()` passes received records to `parse_record()`.
- `parse_record()` dispatches `FCGI_STDIN` directly to `parse_stdin()`.
- `parse_stdin()` only rejected records when `c->id != id`.
- Before `FCGI_BEGIN_REQUEST`, an attacker-supplied `FCGI_STDIN` record with request id `0` matched the zeroed `c->id`.
- Each accepted record allocated a `struct fcgi_stdin`, copied attacker-controlled content into it, and appended it to `c->stdin_head`.
- Repeating the record caused unbounded heap growth until connection cleanup or timeout.

## Why This Is A Real Bug

`FCGI_STDIN` is request data and is only meaningful after a FastCGI request has started. Other request-scoped record handlers already enforce this ordering; for example, `parse_params()` rejects `FCGI_PARAMS` when `request_started` is false. `parse_stdin()` omitted the same state check, allowing the initial zeroed request id to be treated as valid protocol state.

The impact is practical because socket-authorized local processes can hold connections open and accumulate large queued stdin buffers without causing CGI execution or queue draining.

## Fix Requirement

Reject `FCGI_STDIN` records unless:

- `c->request_started` is true.
- The record id matches `c->id`.

## Patch Rationale

The patch adds the missing request-state validation to `parse_stdin()`:

```c
if (!c->request_started || c->id != id) {
	lwarnx("unexpected id, ignoring");
	return;
}
```

This preserves valid stdin handling after `FCGI_BEGIN_REQUEST` while preventing pre-request id-zero records from allocating queue nodes.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/slowcgi/slowcgi.c b/usr.sbin/slowcgi/slowcgi.c
index 9a0f8b5..2752fad 100644
--- a/usr.sbin/slowcgi/slowcgi.c
+++ b/usr.sbin/slowcgi/slowcgi.c
@@ -800,7 +800,7 @@ parse_stdin(uint8_t *buf, uint16_t n, struct request *c, uint16_t id)
 {
 	struct fcgi_stdin	*node;
 
-	if (c->id != id) {
+	if (!c->request_started || c->id != id) {
 		lwarnx("unexpected id, ignoring");
 		return;
 	}
```