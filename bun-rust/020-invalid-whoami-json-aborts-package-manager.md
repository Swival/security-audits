# Invalid whoami JSON Aborts Package Manager

## Classification

Denial of service, medium severity.

## Affected Locations

`src/install/npm.rs:208`

## Summary

`whoami` aborts the package manager process when an attacker-controlled registry returns a malformed JSON body with a 2xx response for `/-/whoami`. The malformed response reaches the JSON parse path and non-OOM parse failures call `Global::crash()` instead of returning a recoverable `WhoamiError`.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The user runs `whoami` against an attacker-controlled or compromised npm registry URL.
- A non-empty auth token is configured, so `whoami` sends `GET {registry}/-/whoami`.
- The registry returns a 2xx status with malformed JSON, such as `not-json`.

## Proof

`whoami` builds a `GET` request to `{registry}/-/whoami` and follows redirects.

`src/install/npm.rs:182` only diverts status codes `>= 400` to `response_error`, so `200 OK` responses continue to the JSON parse path.

`src/install/npm.rs:199` parses the response body:

```rust
let json = match JSON::parse_utf8(&source, &mut log, &bump) {
```

For malformed JSON, only OOM is returned as recoverable. Other parse errors print:

```text
failed to parse '/-/whoami' response body as JSON
```

and call `Global::crash()`.

`src/bun_core/Global.rs:746` implements `Global::crash()` as process termination via `exit(1)`. Therefore, a malicious registry can deterministically terminate `bun pm whoami` by returning malformed JSON with a 2xx status.

## Why This Is A Real Bug

The registry response is attacker-controlled under the stated precondition, and the command explicitly accepts custom registry URLs. A malformed but successful HTTP response should be treated as an invalid authentication or response error, not as an unrecoverable process crash.

The existing function signature already supports recoverable failure:

```rust
pub fn whoami(manager: &mut PackageManager) -> Result<Vec<u8>, WhoamiError>
```

The crash bypasses this error channel and converts remote input into process termination.

## Fix Requirement

Replace the non-OOM malformed JSON crash path with a recoverable `WhoamiError`, preserving OOM handling as `WhoamiError::OutOfMemory`.

## Patch Rationale

The patch changes only the malformed JSON non-OOM arm in `whoami`. It preserves the existing diagnostic output, but returns `WhoamiError::ProbablyInvalidAuth` instead of calling `Global::crash()`.

This matches the existing behavior for parsed JSON that lacks a `username` field, which already returns `WhoamiError::ProbablyInvalidAuth`.

## Residual Risk

None

## Patch

```diff
diff --git a/src/install/npm.rs b/src/install/npm.rs
index 04024fd8d8..1ce7a690ce 100644
--- a/src/install/npm.rs
+++ b/src/install/npm.rs
@@ -205,7 +205,7 @@ pub fn whoami(manager: &mut PackageManager) -> Result<Vec<u8>, WhoamiError> {
                 "failed to parse '/-/whoami' response body as JSON",
                 format_args!(""),
             );
-            Global::crash();
+            return Err(WhoamiError::ProbablyInvalidAuth);
         }
     };
```