# scryptSync Ignores Derivation Errors

## Classification

security_control_failure, high severity, certain confidence

## Affected Locations

`src/runtime/node/node_crypto_binding.rs:1209`

## Summary

`scryptSync` returned a successfully allocated key buffer even when scrypt derivation failed. `Scrypt::run_task_impl` records failures in `self.err`, including oversized password or salt inputs and `EVP_PBE_scrypt` failure, but the synchronous caller did not inspect that error state before returning.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Caller invokes `scryptSync`.
- Password or salt length exceeds `i32::MAX`, or `EVP_PBE_scrypt` otherwise fails.
- Requested `keylen` is non-zero, so an output buffer is allocated and expected to be derived.

## Proof

`Scrypt::run_task_impl` treats password or salt lengths greater than `i32::MAX` as a derivation failure:

```rust
if password.len() > i32::MAX as usize || salt.len() > i32::MAX as usize {
    self.err = Some(0);
    return;
}
```

The same helper also records BoringSSL derivation failure:

```rust
if res == 0 {
    self.err = Some(boringssl::c::ERR_peek_last_error());
    return;
}
```

The asynchronous path checks `self.err` in `run_from_js` and reports `Scrypt failed`, confirming that `err` is intended to be a hard failure.

Before the patch, the synchronous path allocated the result buffer, invoked `ctx.run_task_impl(bytes)`, and immediately returned `Ok(buf)`. Therefore, an oversized password or salt caused `run_task_impl` to set `ctx.err` and return without deriving the key, while `scryptSync` still reported success.

## Why This Is A Real Bug

This is a fail-open condition in a cryptographic key derivation primitive. The implementation explicitly marks the derivation as failed by setting `self.err`, but `scryptSync` ignored that state and returned an underived output buffer as if a KDF had completed successfully.

The async implementation already treats the same state as an error, so the sync implementation was inconsistent with the intended control flow and with the security expectation that failed KDF operations must not produce successful key material.

## Fix Requirement

After `ctx.run_task_impl(bytes)`, `scryptSync` must check `ctx.err` and throw a crypto operation failure instead of returning the output buffer.

## Patch Rationale

The patch adds the missing error check directly after synchronous derivation:

```rust
ctx.run_task_impl(bytes);
if ctx.err.is_some() {
    return Err(global
        .err(
            ErrorCode::CRYPTO_OPERATION_FAILED,
            format_args!("Scrypt failed"),
        )
        .throw());
}
```

This preserves the existing allocation and derivation flow while aligning `scryptSync` with the async path’s failure semantics. Any error recorded by `run_task_impl` now prevents returning the buffer.

## Residual Risk

None

## Patch

`103-scryptsync-ignores-derivation-errors.patch`

```diff
diff --git a/src/runtime/node/node_crypto_binding.rs b/src/runtime/node/node_crypto_binding.rs
index 9002dc704a..4e24df0428 100644
--- a/src/runtime/node/node_crypto_binding.rs
+++ b/src/runtime/node/node_crypto_binding.rs
@@ -1207,6 +1207,14 @@ mod _impl {
         let mut ctx = scopeguard::guard(ctx, |mut c| c.deinit_sync());
         let (buf, bytes) = ArrayBuffer::alloc::<{ JSType::ArrayBuffer }>(global, ctx.keylen)?;
         ctx.run_task_impl(bytes);
+        if ctx.err.is_some() {
+            return Err(global
+                .err(
+                    ErrorCode::CRYPTO_OPERATION_FAILED,
+                    format_args!("Scrypt failed"),
+                )
+                .throw());
+        }
         Ok(buf)
     }
```