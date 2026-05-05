# Non-200 Success Permits Certificate Issuance

## Classification

Security control failure, high severity.

## Affected Locations

`modules/caddytls/ondemand.go:164`

## Summary

`PermissionByHTTP.CertificateAllowed` documents that the HTTP permission endpoint must return `200 OK` to allow on-demand certificate loading or issuance, and that any other status denies it. The implementation instead accepted any `2xx` response as authorization. A permission endpoint returning `204 No Content`, `201 Created`, or another non-200 success status for a denied name was treated as approval, permitting unauthorized on-demand certificate issuance.

## Provenance

This finding was identified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- On-demand TLS is configured to use `PermissionByHTTP`.
- The configured permission endpoint returns a non-200 `2xx` status for a name that should be denied.
- An attacker can trigger on-demand TLS certificate permission checks, for example by requesting a denied SNI/domain.

## Proof

`PermissionByHTTP` is registered as `tls.permission.http` and implements `OnDemandPermission`.

The documented contract in `modules/caddytls/ondemand.go` states:

- `200 OK` allows a certificate.
- Anything else denies it.

The vulnerable implementation performed this check:

```go
if resp.StatusCode < 200 || resp.StatusCode > 299 {
	return fmt.Errorf("%s: %w %s - non-2xx status code %d", name, ErrPermissionDenied, askEndpoint, resp.StatusCode)
}

return nil
```

Because `CertificateAllowed` returns `nil` for allowed certificates, any status from `200` through `299` was accepted. This includes `201 Created` and `204 No Content`, even though the documented control requires exactly `200 OK`.

The reproduced behavior confirms that this `nil` return propagates through the on-demand TLS decision path as approval: errors deny, while no error allows certificate loading or issuance.

## Why This Is A Real Bug

This is a real authorization bypass in the HTTP certificate permission control.

The code’s behavior contradicts its own security contract. Operators may implement the permission endpoint according to the documented rule and return a non-200 `2xx` status to deny a name. Under the vulnerable implementation, that denial fails open because Caddy treats the response as authorization.

The impact is unauthorized on-demand certificate loading or issuance for domains that the permission endpoint intended to reject.

## Fix Requirement

Require the permission endpoint response status to be exactly `http.StatusOK`. Reject every other status code, including all non-200 `2xx` responses.

## Patch Rationale

The patch changes the status check from accepting the entire `2xx` range to accepting only `200 OK`:

```go
if resp.StatusCode != http.StatusOK {
	return fmt.Errorf("%s: %w %s - non-200 status code %d", name, ErrPermissionDenied, askEndpoint, resp.StatusCode)
}
```

This aligns implementation with the documented contract and prevents non-200 success statuses from bypassing the permission control.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/caddytls/ondemand.go b/modules/caddytls/ondemand.go
index 0970234c..a83f4f66 100644
--- a/modules/caddytls/ondemand.go
+++ b/modules/caddytls/ondemand.go
@@ -161,8 +161,8 @@ func (p PermissionByHTTP) CertificateAllowed(ctx context.Context, name string) e
 		)
 	}
 
-	if resp.StatusCode < 200 || resp.StatusCode > 299 {
-		return fmt.Errorf("%s: %w %s - non-2xx status code %d", name, ErrPermissionDenied, askEndpoint, resp.StatusCode)
+	if resp.StatusCode != http.StatusOK {
+		return fmt.Errorf("%s: %w %s - non-200 status code %d", name, ErrPermissionDenied, askEndpoint, resp.StatusCode)
 	}
 
 	return nil
```