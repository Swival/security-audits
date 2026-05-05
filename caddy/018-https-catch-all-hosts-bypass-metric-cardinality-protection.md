# HTTPS catch-all hosts bypass metric cardinality protection

## Classification

denial of service, medium severity, confidence certain

## Affected Locations

- `modules/caddyhttp/metrics_test.go:472`
- `modules/caddyhttp/metrics.go:265`

## Summary

When per-host HTTP metrics are enabled with `ObserveCatchallHosts=false`, unrecognized HTTP hosts are aggregated under `_other` to prevent unbounded Prometheus label cardinality. HTTPS requests bypassed that protection because catch-all HTTPS hosts were allowed when `hasHTTPSServer` was true, causing arbitrary remote-controlled `Host` values to become distinct `host` label values.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `Metrics.PerHost=true`
- `Metrics.ObserveCatchallHosts=false`
- HTTPS server present, setting `hasHTTPSServer=true`
- Catch-all route reachable by requests with arbitrary `Host` headers
- Normal HTTPS behavior where `StrictSNIHost` is not explicitly enabled

## Proof

`TestMetricsHTTPSCatchAll` constructs metrics with:

- `PerHost: true`
- `ObserveCatchallHosts: false`
- `hasHTTPSServer: true`
- empty `allowedHosts`

The test sends two requests with `Host: unknown.com`:

- HTTPS request with `r1.TLS = &tls.ConnectionState{}`
- HTTP request with no TLS state

Before the patch, the expected Prometheus output proved inconsistent behavior:

```text
caddy_http_requests_total{handler="test",host="_other",server="UNKNOWN"} 1
caddy_http_requests_total{handler="test",host="unknown.com",server="UNKNOWN"} 1
```

The HTTPS request retained `host="unknown.com"` while the HTTP request was protected as `host="_other"`.

Additional reproduced evidence confirms exploitability:

- Catch-all routes with no matchers match all requests.
- SNI/Host equality is only enforced when `StrictSNIHost` is explicitly true.
- A remote HTTPS client can complete TLS using a valid SNI, send many requests with distinct arbitrary `Host` headers, and create unbounded Prometheus `host` label series.

## Why This Is A Real Bug

The protection intent is explicit: unrecognized hosts should be aggregated under `_other` unless catch-all host observation is intentionally enabled. The HTTPS exception made the default unsafe for exposed HTTPS servers. TLS certificate presence does not bound HTTP `Host` header values, especially when strict SNI/Host matching is disabled by default. Therefore an attacker can generate many unique `host` label values and exhaust metrics storage or memory.

## Fix Requirement

Map unrecognized HTTPS hosts to `_other` unless `ObserveCatchallHosts` is explicitly true, matching HTTP behavior and preserving only explicitly configured hosts as individual labels.

## Patch Rationale

The patch removes HTTPS auto-allowance from `shouldAllowHostMetrics`:

```go
return m.ObserveCatchallHosts
```

This makes the host-label decision depend only on:

- `PerHost`
- whether the host is explicitly in `allowedHosts`
- whether `ObserveCatchallHosts` is explicitly enabled

The test is updated so both HTTP and HTTPS requests with an unrecognized host produce a single aggregated `_other` series:

```text
caddy_http_requests_total{handler="test",host="_other",server="UNKNOWN"} 2
```

Documentation comments are also corrected to remove the stale HTTPS auto-enable claim and reference `ObserveCatchallHosts`.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/caddyhttp/metrics.go b/modules/caddyhttp/metrics.go
index 8d20e01b..4fdd7a51 100644
--- a/modules/caddyhttp/metrics.go
+++ b/modules/caddyhttp/metrics.go
@@ -57,7 +57,7 @@ type Metrics struct {
 	// CARDINALITY PROTECTION: To prevent unbounded cardinality attacks,
 	// only explicitly configured hosts (via host matchers) are allowed
 	// by default. Other hosts are aggregated under the "_other" label.
-	// See AllowCatchAllHosts to change this behavior.
+	// See ObserveCatchallHosts to change this behavior.
 	PerHost bool `json:"per_host,omitempty"`
 
 	// Allow metrics for catch-all hosts (hosts without explicit configuration).
@@ -65,10 +65,6 @@ type Metrics struct {
 	// will get individual metrics labels. All other hosts will be aggregated
 	// under the "_other" label to prevent cardinality explosion.
 	//
-	// This is automatically enabled for HTTPS servers (since certificates provide
-	// some protection against unbounded cardinality), but disabled for HTTP servers
-	// by default to prevent cardinality attacks from arbitrary Host headers.
-	//
 	// Set to true to allow all hosts to get individual metrics (NOT RECOMMENDED
 	// for production environments exposed to the internet).
 	ObserveCatchallHosts bool `json:"observe_catchall_hosts,omitempty"`
@@ -265,8 +261,7 @@ func (m *Metrics) scanConfigForHosts(app *App) {
 // shouldAllowHostMetrics determines if metrics should be collected for the given host.
 // This implements the cardinality protection by only allowing metrics for:
 // 1. Explicitly configured hosts
-// 2. Catch-all requests on HTTPS servers (if AllowCatchAllHosts is true or auto-enabled)
-// 3. Catch-all requests on HTTP servers only if explicitly allowed
+// 2. Catch-all requests only if explicitly allowed
 func (m *Metrics) shouldAllowHostMetrics(host string, isHTTPS bool) bool {
 	if !m.PerHost {
 		return true // host won't be used in labels anyway
@@ -280,8 +275,7 @@ func (m *Metrics) shouldAllowHostMetrics(host string, isHTTPS bool) bool {
 	}
 
 	// For catch-all requests (not in allowed hosts)
-	allowCatchAll := m.ObserveCatchallHosts || (isHTTPS && m.hasHTTPSServer)
-	return allowCatchAll
+	return m.ObserveCatchallHosts
 }
 
 // serverNameFromContext extracts the current server name from the context.
diff --git a/modules/caddyhttp/metrics_test.go b/modules/caddyhttp/metrics_test.go
index d75b3cae..4e7b14c6 100644
--- a/modules/caddyhttp/metrics_test.go
+++ b/modules/caddyhttp/metrics_test.go
@@ -434,7 +434,7 @@ func TestMetricsCardinalityProtection(t *testing.T) {
 func TestMetricsHTTPSCatchAll(t *testing.T) {
 	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
 
-	// Test that HTTPS requests allow catch-all even when AllowCatchAllHosts is false
+	// Test that HTTPS requests also map unrecognized hosts to "_other" when ObserveCatchallHosts is false
 	metrics := &Metrics{
 		PerHost:              true,
 		ObserveCatchallHosts: false,
@@ -451,7 +451,7 @@ func TestMetricsHTTPSCatchAll(t *testing.T) {
 
 	ih := newMetricsInstrumentedRoute(ctx, "test", h, metrics)
 
-	// Test HTTPS request (should be allowed even though not in allowedHosts)
+	// Test HTTPS request (should be mapped to "_other")
 	r1 := httptest.NewRequest("GET", "https://unknown.com/", nil)
 	r1.Host = "unknown.com"
 	r1.TLS = &tls.ConnectionState{} // Mark as TLS/HTTPS
@@ -465,12 +465,11 @@ func TestMetricsHTTPSCatchAll(t *testing.T) {
 	w2 := httptest.NewRecorder()
 	ih.ServeHTTP(w2, r2)
 
-	// Check that HTTPS request gets real host, HTTP gets "_other"
+	// Check that both HTTPS and HTTP requests get "_other"
 	expected := `
 	# HELP caddy_http_requests_total Counter of HTTP(S) requests made.
 	# TYPE caddy_http_requests_total counter
-	caddy_http_requests_total{handler="test",host="_other",server="UNKNOWN"} 1
-	caddy_http_requests_total{handler="test",host="unknown.com",server="UNKNOWN"} 1
+	caddy_http_requests_total{handler="test",host="_other",server="UNKNOWN"} 2
 	`
 
 	if err := testutil.GatherAndCompare(ctx.GetMetricsRegistry(), strings.NewReader(expected),
```