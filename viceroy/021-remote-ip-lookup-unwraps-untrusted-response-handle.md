# Remote IP lookup unwraps untrusted response handle

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/component/compute/http_resp.rs:274`

## Summary
- `get_remote_ip_addr` accepts a guest-controlled response handle but calls `self.session().response_parts(resp_handle.into()).unwrap()`.
- If the handle is stale, forged, or already consumed, `response_parts(...)` returns `Err`, and the `unwrap()` traps the host instead of returning `None`.
- This creates an unintended termination path for an accessor whose signature implies absence is handled fallibly.

## Provenance
- Verified from the supplied reproducer and source inspection in `src/component/compute/http_resp.rs:274`.
- Cross-checked against the legacy ABI behavior in `src/wiggle_abi/resp_impl.rs:250` and `src/wiggle_abi/resp_impl.rs:287`.
- Scanner reference: https://swival.dev

## Preconditions
- Caller supplies an invalid response handle.
- This occurs in practice after `close` or downstream send consumes the session-side response parts while the guest still retains the resource value.

## Proof
- `resp_handle` is guest-controlled.
- `get_remote_ip_addr` performs `self.session().response_parts(resp_handle.into()).unwrap()` at `src/component/compute/http_resp.rs:274`.
- When the backing response entry is missing, `response_parts(...)` returns `Err(InvalidResponseHandle)`.
- The `unwrap()` panics, producing a host trap rather than the expected `None`.
- Reproducer path:
```text
resp = response.new()
... or obtain resp from an upstream send ...
http-resp.close(resp)
http-resp.response.get-remote-ip-addr(resp)
```
- The same stale-handle condition also arises after send consumes response parts while the Wasmtime resource remains numerically reusable by guest code.

## Why This Is A Real Bug
- The bug is reachable through normal guest-controlled API input, not only internal corruption.
- The component API shape indicates this accessor should report absence via `None`; only selected methods are explicitly trappable.
- The legacy ABI already handles equivalent invalid-handle cases fallibly, so the current panic is inconsistent behavior and an observable regression in robustness.
- A stale or forged handle can therefore terminate execution unexpectedly, which is a real availability impact.

## Fix Requirement
- Replace the `unwrap()` on `response_parts(...)` with fallible handling.
- Return `None` when the response handle is invalid or no response parts are available.
- Preserve existing successful behavior for valid handles.

## Patch Rationale
- Converting the lookup to fallible handling aligns implementation with the accessor’s optional return type.
- It removes the unintended trap path for guest-controlled invalid handles.
- It also restores consistency with the existing legacy ABI behavior for equivalent lookups.

## Residual Risk
- None

## Patch
```patch
*** Begin Patch
*** Add File: 021-remote-ip-lookup-unwraps-untrusted-response-handle.patch
diff --git a/src/component/compute/http_resp.rs b/src/component/compute/http_resp.rs
index 0000000..0000000 100644
--- a/src/component/compute/http_resp.rs
+++ b/src/component/compute/http_resp.rs
@@ -271,7 +271,10 @@ impl Host for ComputeHttpResponse {
     fn get_remote_ip_addr(
         &mut self,
         resp_handle: Resource<ResponseHandle>,
     ) -> Option<IpAddr> {
-        let resp = self.session().response_parts(resp_handle.into()).unwrap();
+        let resp = match self.session().response_parts(resp_handle.into()) {
+            Ok(resp) => resp,
+            Err(_) => return None,
+        };
         resp.get_remote_addr().map(|addr| addr.ip().into())
     }
*** End Patch
```