# Trap Details Exposed In HTTP 500 Body

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/execute.rs:856`
- `src/execute.rs:1080`

## Summary
A guest Wasm trap is converted into an HTTP 500 response whose body is built from the trap error's debug string. Because Wasmtime backtrace details are enabled, client-visible 500 bodies can disclose internal trap diagnostics, including Wasm backtrace frames and trap reasons.

## Provenance
- Verified from the provided reproducer and patch context
- Reference: https://swival.dev

## Preconditions
- A guest request reaches a Wasm trap during execution

## Proof
The request path maps `ExecutionError::WasmTrap(e)` to `anyhow_response(&e)` at `src/execute.rs:856`. `anyhow_response` constructs the HTTP 500 body from `format!("{err:?}")`, so the error debug representation is returned verbatim to the client.

Wasmtime is configured with backtrace details enabled at `src/execute.rs:1080`, which causes trap formatting to include execution backtrace data. Using the committed trapping guest at `cli/tests/wasm/trapping.wat:1`, one HTTP request produced:

```text
error while executing at wasm backtrace:
    0:     0x23 - <unknown>!_start

Caused by:
    wasm trap: wasm `unreachable` instruction executed
```

The observed response was `HTTP/1.1 500 Internal Server Error` with `content-length: 142`, confirming the trap details were returned in the response body.

## Why This Is A Real Bug
The response exposes internal runtime diagnostics to untrusted clients. The leaked body includes Wasm backtrace information and trap cause text, which reveals guest execution details that should remain server-side. This violates the expected separation between internal error reporting and external HTTP error responses.

## Fix Requirement
Return a generic HTTP 500 body for Wasm trap failures and keep detailed trap diagnostics in server-side logs only.

## Patch Rationale
The patch should remove client-facing use of the trap debug string on the Wasm-trap path and replace it with a fixed generic 500 response body. Detailed trap information remains available through logging, preserving operability without exposing internals to clients.

## Residual Risk
None

## Patch
- `001-trap-details-returned-in-http-500-body.patch`