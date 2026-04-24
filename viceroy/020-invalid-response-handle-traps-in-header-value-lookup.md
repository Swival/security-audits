# Invalid response handle traps in header value lookup

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/component/compute/http_resp.rs:146`

## Summary
`get_header_values` unwraps `response_parts` for a guest-supplied response handle, so an invalid or stale handle panics the host path instead of returning the typed `types::Error` used by sibling response-handle APIs.

## Provenance
- Verified finding reproduced from Swival Security Scanner: https://swival.dev
- Reproducer confirms reachability via guest-controlled response handles and observable trap behavior.

## Preconditions
- Guest can call response header lookup with an invalid response handle.
- A practical sequence is: create a response handle, invalidate it via `close` or `send_downstream*`, then call `get-header-values` on the stale handle.

## Proof
At `src/component/compute/http_resp.rs:146`, guest input `h` flows into:
```rust
self.session().response_parts(h.into()).unwrap()
```
If `h` is invalid, `response_parts` returns an error. The `unwrap()` converts that ordinary invalid-handle condition into a panic/trap. The reproduced path shows this is reachable by obtaining a valid handle from `response::new`, invalidating it, and then invoking `get-header-values` again. The component hostcall is trappable and manifests as an instance abort rather than `Result::Err(types::Error)`.

## Why This Is A Real Bug
This is externally reachable from hostcall input and changes API behavior from typed error propagation to an untyped trap. That causes denial of service for the current execution and violates the established contract used elsewhere in the same component and in the legacy wiggle implementation, which propagates invalid handle errors with `?`.

## Fix Requirement
Replace the `unwrap()` on `response_parts` with `?` so invalid handles propagate as `types::Error` instead of trapping.

## Patch Rationale
The patch changes the invalid-handle path from panic-based control flow to normal error propagation, aligning `get_header_values` with neighboring APIs and the legacy implementation. This preserves behavior for valid handles while restoring the expected typed failure mode for stale or malformed handles.

## Residual Risk
None

## Patch
Saved as `020-invalid-response-handle-traps-in-header-value-lookup.patch`.

```diff
diff --git a/src/component/compute/http_resp.rs b/src/component/compute/http_resp.rs
--- a/src/component/compute/http_resp.rs
+++ b/src/component/compute/http_resp.rs
@@ -146,7 +146,7 @@ impl Host for ComponentCtx {
     fn get_header_values(
         &mut self,
         h: types::ResponseHandle,
         name: http_types::HeaderName,
     ) -> wasmtime::Result<Result<Vec<http_types::HeaderValue>, types::Error>> {
-        let parts = self.session().response_parts(h.into()).unwrap();
+        let parts = self.session().response_parts(h.into())?;
         Ok(Ok(
             parts
                 .headers
```