# Explicit Managers Disable On-Demand Issuance Fail-Closed

## Classification

Policy bypass, high severity.

## Affected Locations

`modules/caddytls/automation.go:303`

## Summary

Wildcard or default public-issuer automation policies with an explicit certificate manager and no on-demand permission module incorrectly allowed fallback on-demand issuance for arbitrary SNI names. Explicit managers enabled on-demand TLS, but also disabled the intended fail-closed issuer permission gate when managers returned no certificate.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Automation policy is wildcard or default/catch-all.
- Policy uses public issuance, not only the internal issuer.
- Policy has an explicit `get_certificate` manager.
- No on-demand permission module is configured.
- The configured manager returns no certificate for the requested SNI.

## Proof

`makeCertMagicConfig` enables on-demand TLS when either `ap.OnDemand` is true or managers are present:

```go
if ap.OnDemand || len(ap.Managers) > 0 {
```

For wildcard/default public issuance without a permission module, `noProtections` is true:

```go
noProtections := ap.isWildcardOrDefault() && !ap.onlyInternalIssuer() && (tlsApp.Automation == nil || tlsApp.Automation.OnDemand == nil || tlsApp.Automation.OnDemand.permission == nil)
```

Before the patch, `failClosed` was disabled whenever managers were explicitly configured:

```go
failClosed := noProtections && !ap.hadExplicitManagers
```

`Provision` sets `hadExplicitManagers` when `ManagersRaw` is configured, so the `DecisionFunc` did not return the fail-closed error. If `Automation.OnDemand` or its permission module was absent, the decision function returned `nil`, allowing issuance for the SNI.

The reproduced path confirms remote reachability:

- `modules/caddytls/connpolicy.go:294` selects the automation policy config from ClientHello SNI.
- `modules/caddytls/connpolicy.go:316` passes that config into CertMagic certificate retrieval.
- `modules/caddytls/tls.go:775` and `modules/caddytls/tls.go:777` make a default/catch-all policy match arbitrary SNI.
- `modules/caddytls/certmanagers.go:45` and `modules/caddytls/certmanagers.go:48` show Tailscale returns `nil` for unmanaged names.
- `modules/caddytls/certmanagers.go:163` shows the HTTP manager returns `nil` on HTTP 204.

A temporary unit test confirmed that a no-op manager returned `nil`, `DecisionFunc` allowed `attacker.example.com`, and a fake issuer was invoked for that exact SNI.

## Why This Is A Real Bug

The code comment states that when no permission module is configured, managers may be used but issuer fallback must not be allowed. The implementation contradicted that intent by making explicit managers suppress fail-closed behavior.

This lets an untrusted remote TLS client send crafted SNI during a handshake and trigger on-demand public issuance attempts for attacker-chosen valid names. That bypasses the permission gate intended to prevent ACME, storage, and rate-limit abuse.

## Fix Requirement

Keep fail-closed behavior enabled for issuer fallback whenever wildcard/default public on-demand TLS lacks a permission module, including when explicit managers are configured.

## Patch Rationale

The patch changes `failClosed` to depend only on `noProtections`:

```go
failClosed := noProtections
```

This preserves the existing configuration behavior:

- No managers and no permission module still fails provisioning as a config error.
- Explicit managers may still enable on-demand TLS.
- If managers do not provide a certificate, issuer fallback is denied without a permission module.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/caddytls/automation.go b/modules/caddytls/automation.go
index 5b7a4ed5..672012ca 100644
--- a/modules/caddytls/automation.go
+++ b/modules/caddytls/automation.go
@@ -300,7 +300,7 @@ func (ap *AutomationPolicy) makeCertMagicConfig(tlsApp *TLS, issuers []certmagic
 		// prevent issuance from Issuers (when Managers don't provide a certificate) if there's no
 		// permission module configured
 		noProtections := ap.isWildcardOrDefault() && !ap.onlyInternalIssuer() && (tlsApp.Automation == nil || tlsApp.Automation.OnDemand == nil || tlsApp.Automation.OnDemand.permission == nil)
-		failClosed := noProtections && !ap.hadExplicitManagers // don't allow on-demand issuance (other than implicit managers) if no managers have been explicitly configured
+		failClosed := noProtections // don't allow on-demand issuance when no permission module is configured
 		if noProtections {
 			if !ap.hadExplicitManagers {
 				// no managers, no explicitly-configured permission module, this is a config error
```