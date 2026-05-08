# Remote HTTP Response Line Exhausts Memory

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`usr.bin/ftp/fetch.c:796`

`usr.bin/ftp/fetch.c:875`

## Summary

`ftp` reads HTTP status and header lines from remote HTTP/HTTPS peers with unbounded `getline()`. An attacker-controlled server can send a status or header line without a newline, causing repeated buffer growth until memory exhaustion, allocation failure, or a hung retrieval before download handling begins.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

The user fetches an `http://` or `https://` URL from an attacker-controlled server.

## Proof

`auto_fetch()` routes user-supplied HTTP and HTTPS URLs into `url_get()` at `usr.bin/ftp/fetch.c:1312`.

After sending the HTTP request, `url_get()` initializes `buf = NULL` and `bufsize = 0`, then reads the status line with:

```c
getline(&buf, &bufsize, fin)
```

The same unbounded read is used again in the HTTP header loop before output file creation and body transfer handling.

A malicious server can respond with:

```http
HTTP/1.1 200 OK\r\n
X:
```

followed by an arbitrarily long byte stream without `\n`. Because `getline()` reads until newline or EOF, it keeps reallocating `buf` under attacker-controlled input. The later `128 * 1024` transfer buffer is only used after headers complete, so it does not constrain this path.

## Why This Is A Real Bug

The remote server fully controls the bytes consumed by `getline()`. There is no status-line or header-line length limit, no bounded read, and no early rejection of overlong HTTP metadata. The vulnerable reads occur before normal download processing, so a client can be forced to consume memory without ever receiving a file body.

## Fix Requirement

Replace unbounded HTTP status/header `getline()` calls with bounded line reads. Reject any HTTP response line or header line that reaches the configured maximum without a terminating newline.

## Patch Rationale

The patch introduces `HTTP_LINE_MAX` with an 8192-byte limit for HTTP status and header lines.

It allocates a fixed response-line buffer once, replaces both vulnerable `getline()` calls with `fgets(buf, HTTP_LINE_MAX + 1, fin)`, and rejects lines where the buffer fills without seeing `\n`.

This bounds memory usage for attacker-controlled HTTP metadata while preserving existing parsing behavior for normal responses.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ftp/fetch.c b/usr.bin/ftp/fetch.c
index 453f6fd..1f9906d 100644
--- a/usr.bin/ftp/fetch.c
+++ b/usr.bin/ftp/fetch.c
@@ -94,6 +94,7 @@ static int	stdio_tls_read_wrapper(void *, char *, int);
 #define	FILE_URL	"file:"		/* file URL prefix */
 #define FTP_PROXY	"ftp_proxy"	/* env var with ftp proxy location */
 #define HTTP_PROXY	"http_proxy"	/* env var with http proxy location */
+#define HTTP_LINE_MAX	8192		/* max HTTP status/header line */
 
 #define EMPTYSTRING(x)	((x) == NULL || (*(x) == '\0'))
 
@@ -321,7 +322,6 @@ url_get(const char *origline, const char *proxyenv, const char *outfile, int las
 	off_t hashbytes;
 	const char *errstr;
 	ssize_t len, wlen;
-	size_t bufsize;
 	char *proxyhost = NULL;
 #ifndef NOSSL
 	char *sslpath = NULL, *sslhost = NULL;
@@ -787,16 +787,22 @@ noslash:
 	free(buf);
 #endif /* !NOSSL */
 	buf = NULL;
-	bufsize = 0;
+	if ((buf = malloc(HTTP_LINE_MAX + 1)) == NULL)
+		errx(1, "Can't allocate memory for HTTP response");
 
 	if (fflush(fin) == EOF) {
 		warnx("Writing HTTP request: %s", sockerror(tls));
 		goto cleanup_url_get;
 	}
-	if ((len = getline(&buf, &bufsize, fin)) == -1) {
+	if (fgets(buf, HTTP_LINE_MAX + 1, fin) == NULL) {
 		warnx("Receiving HTTP reply: %s", sockerror(tls));
 		goto cleanup_url_get;
 	}
+	len = strlen(buf);
+	if (len == HTTP_LINE_MAX && buf[len - 1] != '\n') {
+		warnx("HTTP response line too long");
+		goto cleanup_url_get;
+	}
 
 	while (len > 0 && (buf[len-1] == '\r' || buf[len-1] == '\n'))
 		buf[--len] = '\0';
@@ -872,10 +878,15 @@ noslash:
 	filesize = -1;
 
 	for (;;) {
-		if ((len = getline(&buf, &bufsize, fin)) == -1) {
+		if (fgets(buf, HTTP_LINE_MAX + 1, fin) == NULL) {
 			warnx("Receiving HTTP reply: %s", sockerror(tls));
 			goto cleanup_url_get;
 		}
+		len = strlen(buf);
+		if (len == HTTP_LINE_MAX && buf[len - 1] != '\n') {
+			warnx("HTTP header line too long");
+			goto cleanup_url_get;
+		}
 
 		while (len > 0 && (buf[len-1] == '\r' || buf[len-1] == '\n' ||
 		    buf[len-1] == ' ' || buf[len-1] == '\t'))
```