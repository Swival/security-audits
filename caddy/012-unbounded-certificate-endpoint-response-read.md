# Unbounded Certificate Endpoint Response Read

## Classification

Denial of service, medium severity.

## Affected Locations

`modules/caddytls/certmanagers.go:171`

## Summary

`HTTPCertGetter.GetCertificate` reads an HTTP certificate endpoint response with `io.ReadAll(resp.Body)` after a `200 OK` response. The read has no size bound, so an attacker-controlled configured endpoint can stream an arbitrarily large PEM body and force unbounded memory allocation during TLS certificate retrieval.

## Provenance

Verified from the supplied source, reproduced behavior, and patch.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Caddy is configured with `tls.get_certificate.http` using an attacker-controlled or malicious certificate endpoint.

## Proof

`HTTPCertGetter.GetCertificate` constructs a URL using TLS ClientHello values, creates an HTTP GET request, and sends it through `http.DefaultClient.Do`.

If the endpoint returns `200 OK`, execution passes the status checks and reaches:

```go
bodyBytes, err := io.ReadAll(resp.Body)
```

Because `resp.Body` is attacker-controlled and no `Content-Length` check, `LimitReader`, `MaxBytesReader`, timeout, or other size bound is applied, `io.ReadAll` continues allocating until EOF. A malicious endpoint can stream an arbitrarily large response before certificate parsing occurs, exhausting memory in the Caddy process during TLS handshakes.

## Why This Is A Real Bug

The vulnerable read happens on the certificate retrieval path for `tls.get_certificate.http`. A remote TLS handshake can trigger this path when the manager is configured, and the configured HTTP backend fully controls the response body. `io.ReadAll` is explicitly unbounded and accumulates the entire response in memory, making memory exhaustion practical with a large or non-terminating `200 OK` response.

## Fix Requirement

Bound the maximum certificate response size before reading the body into memory, and fail closed when the response exceeds that limit.

## Patch Rationale

The patch wraps `resp.Body` with `io.LimitReader(resp.Body, maxCertBundleSize+1)` before calling `io.ReadAll`. Reading one byte beyond the configured maximum allows the code to distinguish an exactly valid maximum-sized response from an oversized response.

The chosen limit is:

```go
const maxCertBundleSize = 1 << 20
```

If the response exceeds 1 MiB, the function returns:

```go
certificate response body exceeded 1048576 bytes
```

This preserves existing behavior for normal PEM certificate bundles while preventing unbounded allocation.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/caddytls/certmanagers.go b/modules/caddytls/certmanagers.go
index 68014635..e8177d24 100644
--- a/modules/caddytls/certmanagers.go
+++ b/modules/caddytls/certmanagers.go
@@ -168,10 +168,14 @@ func (hcg HTTPCertGetter) GetCertificate(ctx context.Context, hello *tls.ClientH
 		return nil, fmt.Errorf("got HTTP %d", resp.StatusCode)
 	}
 
-	bodyBytes, err := io.ReadAll(resp.Body)
+	const maxCertBundleSize = 1 << 20
+	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxCertBundleSize+1))
 	if err != nil {
 		return nil, fmt.Errorf("error reading response body: %v", err)
 	}
+	if len(bodyBytes) > maxCertBundleSize {
+		return nil, fmt.Errorf("certificate response body exceeded %d bytes", maxCertBundleSize)
+	}
 
 	cert, err := tlsCertFromCertAndKeyPEMBundle(bodyBytes)
 	if err != nil {
```