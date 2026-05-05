# Configured TLS server_name is ignored

## Classification

Policy bypass, medium severity. Confidence: certain.

## Affected Locations

`modules/caddytls/capools.go:621`

## Summary

`HTTPCertPool` supports a TLS `server_name` override for HTTPS certificate-bundle endpoints, but the generated client TLS configuration ignores that field. The code expands placeholders from `cfg.ServerName`, which is still empty, instead of `t.ServerName`, where the configured value is stored.

As a result, Go's HTTP client verifies the remote certificate against the URL host rather than the operator-configured TLS identity. If the endpoint is attacker-controlled or malicious, it can present a certificate valid for the URL host and still supply PEM roots that Caddy adds to the trust pool.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `HTTPCertPool` is configured with an HTTPS endpoint.
- The `tls` block sets `server_name` to an expected identity different from the endpoint URL host.
- The HTTPS endpoint is attacker-controlled or otherwise malicious.

## Proof

`TLSConfig.unmarshalCaddyfile` stores the configured override in `t.ServerName`:

```go
case "server_name":
	if !d.Args(&t.ServerName) {
		return d.ArgErr()
	}
```

`HTTPCertPool.Provision` builds the HTTP transport from `hcp.TLS.makeTLSClientConfig(ctx)` before fetching the configured endpoints.

Inside `makeTLSClientConfig`, the vulnerable assignment is:

```go
cfg.ServerName = repl.ReplaceKnown(cfg.ServerName, "")
```

At that point, `cfg.ServerName` is empty because `cfg` was freshly allocated with `cfg := new(tls.Config)`. Therefore the configured `t.ServerName` value is never copied into the client TLS config.

The reproduced behavior confirms that `TLSConfig{ServerName: "expected.example"}.makeTLSClientConfig(...)` produces no effective `ServerName`. With no other TLS settings, the config can be considered empty and return `nil`; with other TLS settings, `ServerName` remains empty. In either case, Go verifies the server certificate against the endpoint URL host.

After a successful HTTPS response, certificates from the response body are added directly to the trust pool:

```go
caPool.AddCert(cert)
```

## Why This Is A Real Bug

The documented and parsed `server_name` option is a hostname verification policy control. Ignoring it changes the security decision from "verify the certificate against the configured expected identity" to "verify the certificate against the URL host."

For `HTTPCertPool`, the fetched PEM certificates become trusted CA material. A malicious configured HTTPS certificate-bundle endpoint with a certificate valid for the URL host can therefore bypass the configured hostname policy and supply trusted roots, despite the operator requiring a different TLS identity.

## Fix Requirement

Use the configured `TLSConfig.ServerName` field when populating the client `tls.Config.ServerName`:

```go
cfg.ServerName = repl.ReplaceKnown(t.ServerName, "")
```

## Patch Rationale

The patch copies the configured `server_name` value from `t.ServerName` into the generated `tls.Config`, preserving existing placeholder replacement behavior. This makes the HTTPS client enforce the operator-configured TLS identity during certificate verification.

No other TLS behavior changes: custom CAs, renegotiation, insecure skip verify, and empty-config detection remain otherwise unchanged.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/caddytls/capools.go b/modules/caddytls/capools.go
index c275f7d6..ef40f088 100644
--- a/modules/caddytls/capools.go
+++ b/modules/caddytls/capools.go
@@ -618,7 +618,7 @@ func (t *TLSConfig) makeTLSClientConfig(ctx caddy.Context) (*tls.Config, error)
 	}
 
 	// override for the server name used verify the TLS handshake
-	cfg.ServerName = repl.ReplaceKnown(cfg.ServerName, "")
+	cfg.ServerName = repl.ReplaceKnown(t.ServerName, "")
 
 	// throw all security out the window
 	cfg.InsecureSkipVerify = t.InsecureSkipVerify
```