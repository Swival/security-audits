# Malformed FastCGI Header Bypasses HTTP Response Framing

## Classification

Request smuggling / HTTP response framing violation.

Severity: medium.

Confidence: certain.

## Affected Locations

- `httpd/server_fcgi.c:558`
- `httpd/server_fcgi.c:575`
- `httpd/server_fcgi.c:599`
- `httpd/server_fcgi.c:792`
- `httpd/server_fcgi.c:826`

## Summary

A malicious FastCGI backend can send a colonless `FCGI_STDOUT` header line followed by crafted HTTP bytes. `httpd` consumes the malformed line, leaves the following bytes buffered, fails to mark FastCGI headers complete, but still forwards the remaining backend-controlled buffer to the client. This allows raw backend bytes to reach the client before `httpd` emits a valid HTTP response status line and headers.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `httpd` proxies a request to an attacker-controlled or compromised FastCGI backend.
- The backend can emit malformed FastCGI stdout header content.
- The malformed header block contains a colonless line followed by attacker-controlled bytes.

## Proof

`server_fcgi_read()` handles `FCGI_STDOUT` by calling `server_fcgi_getheaders()` while `clt->clt_fcgi.headersdone` is false.

In `server_fcgi_getheaders()`, each line is consumed with `evbuffer_getline()`. When a colonless line is encountered, `strchr(key, ':')` returns `NULL`, the parser breaks, and the function returns false. The malformed line has already been consumed, but following bytes remain in `clt->clt_srvevb`.

Back in `server_fcgi_read()`, `headersdone` remains false. Because the evbuffer is still non-empty, control falls through into the shared `FCGI_STDOUT` / `FCGI_END_REQUEST` send path. `server_fcgi_header()` is skipped because `headersdone` is false, but `server_fcgi_writechunk()` is still called.

`server_fcgi_writechunk()` then writes the remaining backend-controlled bytes to the client. For HTTP/1.0, those bytes are sent directly before any `httpd` response headers. For HTTP/1.1, they are emitted as chunk data before any response status line, still violating HTTP response framing.

## Why This Is A Real Bug

FastCGI response headers are required to be parsed and converted into a valid HTTP response before body bytes are sent to the client. A malformed FastCGI header must terminate the response with an error, not cause the parser to leave attacker-controlled bytes in the output buffer.

The reproduced behavior shows:

- `server_fcgi_getheaders()` consumes the colonless line and returns false.
- Remaining attacker-controlled bytes stay in `clt->clt_srvevb`.
- `server_fcgi_read()` does not abort on the malformed header.
- `server_fcgi_header()` is skipped.
- `server_fcgi_writechunk()` forwards the remaining bytes to the client.

This is a concrete response framing bypass when the FastCGI backend is attacker-controlled.

## Fix Requirement

Abort the FastCGI request on any malformed response header before any buffered backend bytes can be forwarded to the client.

## Patch Rationale

The patch changes `server_fcgi_getheaders()` so a colonless header line is treated as a fatal parse error and returns `-1` immediately after freeing the consumed line.

`server_fcgi_read()` now stores the parser return value, checks for `-1`, and calls `server_abort_http(clt, 500, "malformed fcgi headers")` before reaching the send path. Valid incomplete headers still return `0`, and successfully completed headers still set `headersdone` to `1`.

This preserves existing behavior for valid FastCGI responses while preventing malformed headers from reaching `server_fcgi_writechunk()` with unframed backend-controlled data.

## Residual Risk

None

## Patch

```diff
diff --git a/httpd/server_fcgi.c b/httpd/server_fcgi.c
index 5c4a8d3..b1a4666 100644
--- a/httpd/server_fcgi.c
+++ b/httpd/server_fcgi.c
@@ -520,6 +520,7 @@ server_fcgi_read(struct bufferevent *bev, void *arg)
 	struct client			*clt = (struct client *) arg;
 	struct fcgi_record_header	*h;
 	size_t				 len;
+	int				 ret;
 	char				*ptr;
 
 	do {
@@ -575,8 +576,13 @@ server_fcgi_read(struct bufferevent *bev, void *arg)
 			case FCGI_STDOUT:
 				++clt->clt_chunk;
 				if (!clt->clt_fcgi.headersdone) {
-					clt->clt_fcgi.headersdone =
-					    server_fcgi_getheaders(clt);
+					ret = server_fcgi_getheaders(clt);
+					if (ret == -1) {
+						server_abort_http(clt, 500,
+						    "malformed fcgi headers");
+						return;
+					}
+					clt->clt_fcgi.headersdone = ret;
 					if (!EVBUFFER_LENGTH(clt->clt_srvevb))
 						break;
 				}
@@ -826,8 +832,10 @@ server_fcgi_getheaders(struct client *clt)
 	while ((line = evbuffer_getline(evb)) != NULL && *line != '\0') {
 		key = line;
 
-		if ((value = strchr(key, ':')) == NULL)
-			break;
+		if ((value = strchr(key, ':')) == NULL) {
+			free(line);
+			return (-1);
+		}
 
 		*value++ = '\0';
 		value += strspn(value, " \t");
```