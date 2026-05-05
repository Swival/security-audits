# unbounded adapt request body buffering

## Classification

Denial of service, medium severity.

## Affected Locations

`caddyconfig/load.go:149`

## Summary

The `/adapt` admin API endpoint buffered the entire request body with `io.Copy(buf, r.Body)` before applying any size limit. A client authorized to call `/adapt` could submit an oversized POST body and force unbounded memory growth before config adaptation or validation occurred.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

An attacker can reach and use the Caddy admin API `/adapt` endpoint.

## Proof

`handleAdapt` accepts POST requests on the `/adapt` admin route, obtains a pooled `bytes.Buffer`, then copies the full request body into memory:

```go
_, err := io.Copy(buf, r.Body)
```

Before the patch, this path had no `http.MaxBytesReader`, `io.LimitReader`, `Content-Length` check, or equivalent body-size cap. The buffered bytes were then passed to `adaptByContentType`.

The reproduced evidence confirms:

- The vulnerable body copy occurs before adaptation or validation in `caddyconfig/load.go`.
- No body-size limit exists on this `/adapt` path.
- Admin server header and timeout settings do not cap request body bytes.
- Remote admin access controls can authorize specific methods and paths, including `/adapt`.
- A reachable authorized client can drive memory growth by sending a sufficiently large request body, including through concurrent requests.

## Why This Is A Real Bug

This is a real denial-of-service condition because request body size is attacker-controlled while buffering is process-memory-backed and unbounded. Timeouts only limit duration, not the number of bytes accumulated before adaptation. Access control does not eliminate the issue because authorized or exposed admin API clients can still trigger resource exhaustion.

The neighboring admin config write path already uses a 100 MB request-body cap, demonstrating that large admin request bodies are expected to be bounded.

## Fix Requirement

Cap `/adapt` request bodies before buffering and return HTTP `413 Request Entity Too Large` when the cap is exceeded.

## Patch Rationale

The patch wraps `r.Body` with `http.MaxBytesReader` before `io.Copy`, enforcing a 100 MB maximum on `/adapt` request bodies:

```go
const maxConfigSize = 100 * 1024 * 1024 // 100 MB
r.Body = http.MaxBytesReader(w, r.Body, maxConfigSize)
```

It also detects `*http.MaxBytesError` with `errors.As` and maps that case to `http.StatusRequestEntityTooLarge`, while preserving `400 Bad Request` for other read failures. This prevents unbounded buffering and gives clients an accurate status code when the request exceeds the configured cap.

## Residual Risk

None

## Patch

`015-unbounded-adapt-request-body-buffering.patch`

```diff
diff --git a/caddyconfig/load.go b/caddyconfig/load.go
index d2498ed6..e2db4574 100644
--- a/caddyconfig/load.go
+++ b/caddyconfig/load.go
@@ -17,6 +17,7 @@ package caddyconfig
 import (
 	"bytes"
 	"encoding/json"
+	"errors"
 	"fmt"
 	"io"
 	"mime"
@@ -146,10 +147,18 @@ func (adminLoad) handleAdapt(w http.ResponseWriter, r *http.Request) error {
 	buf.Reset()
 	defer bufPool.Put(buf)
 
+	const maxConfigSize = 100 * 1024 * 1024 // 100 MB
+	r.Body = http.MaxBytesReader(w, r.Body, maxConfigSize)
+
 	_, err := io.Copy(buf, r.Body)
 	if err != nil {
+		status := http.StatusBadRequest
+		var maxBytesErr *http.MaxBytesError
+		if errors.As(err, &maxBytesErr) {
+			status = http.StatusRequestEntityTooLarge
+		}
 		return caddy.APIError{
-			HTTPStatus: http.StatusBadRequest,
+			HTTPStatus: status,
 			Err:        fmt.Errorf("reading request body: %v", err),
 		}
 	}
```