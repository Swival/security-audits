# Unbounded Health-Check Body Read

## Classification

denial of service, medium severity

## Affected Locations

`modules/caddyhttp/reverseproxy/healthchecks.go:545`

## Summary

Active reverse-proxy health checks can read an unbounded backend-controlled response body into memory when `expect_body` is configured and `max_size` is unset. A malicious or compromised upstream can return an oversized successful health-check response and force Caddy to allocate memory for the full body before regex matching, causing process memory exhaustion.

## Provenance

Reproduced and patched from a Swival Security Scanner finding: https://swival.dev

Confidence: certain.

## Preconditions

- Active health checks are enabled.
- `expect_body` is configured.
- `max_size` is unset or non-positive.
- The configured upstream backend is malicious, compromised, or otherwise able to return an oversized health-check response.

## Proof

`ActiveHealthChecks.Provision` compiles `ExpectBody` into `bodyRegexp`, enabling response-body matching.

In `doActiveHealthCheck`, the health-check request is sent to the configured upstream. Before the patch, the response body handling was:

```go
var body io.Reader = resp.Body
if h.HealthChecks.Active.MaxSize > 0 {
	body = io.LimitReader(body, h.HealthChecks.Active.MaxSize)
}
```

When `max_size` was unset, `MaxSize` remained `0`, so `body` stayed as the raw `resp.Body`.

If the response status passed health-check criteria and `bodyRegexp` was non-nil, the code then executed:

```go
bodyBytes, err := io.ReadAll(body)
```

Because `body` was not capped, `io.ReadAll` buffered the entire backend-controlled response before regex matching. An upstream returning a very large successful response could therefore drive unbounded allocation in the Caddy process.

## Why This Is A Real Bug

The response body is controlled by the upstream backend, while the memory allocation occurs inside the Caddy process. The configured `expect_body` path requires full buffering before regex evaluation, and the previous default behavior imposed no maximum read size unless the operator explicitly configured `max_size`.

This creates an attacker-triggerable denial of service under the stated preconditions.

## Fix Requirement

Always cap active health-check body reads before `io.ReadAll`, including when `max_size` is unset. The cap must use a safe default while preserving the explicit configured limit when `max_size > 0`.

## Patch Rationale

The patch introduces a default active health-check body cap:

```go
const defaultActiveHealthCheckMaxSize = 1 << 20
```

It then normalizes the effective limit before body processing:

```go
maxSize := h.HealthChecks.Active.MaxSize
if maxSize <= 0 {
	maxSize = defaultActiveHealthCheckMaxSize
}
body := io.LimitReader(resp.Body, maxSize)
```

This preserves existing configured behavior for positive `max_size` values and prevents unbounded reads when the option is unset or non-positive. The `io.ReadAll(body)` call can now allocate at most the effective capped size.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/caddyhttp/reverseproxy/healthchecks.go b/modules/caddyhttp/reverseproxy/healthchecks.go
index 73604f91..7180e4d5 100644
--- a/modules/caddyhttp/reverseproxy/healthchecks.go
+++ b/modules/caddyhttp/reverseproxy/healthchecks.go
@@ -67,6 +67,8 @@ type HealthChecks struct {
 	Passive *PassiveHealthChecks `json:"passive,omitempty"`
 }
 
+const defaultActiveHealthCheckMaxSize = 1 << 20
+
 // ActiveHealthChecks holds configuration related to active
 // health checks (that is, health checks which occur in a
 // background goroutine independently).
@@ -517,10 +519,11 @@ func (h *Handler) doActiveHealthCheck(dialInfo DialInfo, hostAddr string, networ
 		markUnhealthy()
 		return nil
 	}
-	var body io.Reader = resp.Body
-	if h.HealthChecks.Active.MaxSize > 0 {
-		body = io.LimitReader(body, h.HealthChecks.Active.MaxSize)
+	maxSize := h.HealthChecks.Active.MaxSize
+	if maxSize <= 0 {
+		maxSize = defaultActiveHealthCheckMaxSize
 	}
+	body := io.LimitReader(resp.Body, maxSize)
 	defer func() {
 		// drain any remaining body so connection could be re-used
 		_, _ = io.Copy(io.Discard, body)
```