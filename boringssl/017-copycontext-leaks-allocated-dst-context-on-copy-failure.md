# CopyContext leaks allocated dst context on copy failure

## Classification
- Type: resource lifecycle bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `crypto/evp/p_mldsa.cc:329`

## Summary
`CopyContext` initializes `dst` and allocates a new `MldsaPkeyCtx`, then calls `dctx->context.CopyFrom(sctx->context)`. When that copy fails, the function returns `0` without cleaning up the newly allocated destination context. In the practical caller path, `EVP_PKEY_CTX_dup` nulls `pmeth` before unwinding, which suppresses destructor-driven cleanup and leaves the allocation leaked.

## Provenance
- Verified by reproduction against the current codebase
- Source-backed analysis and patch prepared from local inspection
- Reference: [Swival Security Scanner](https://swival.dev)

## Preconditions
- `Init(dst)` succeeds
- `dctx->context.CopyFrom(...)` fails

## Proof
`CopyContext` calls `Init(dst, nullptr)` at `crypto/evp/p_mldsa.cc:329`, which allocates and stores a new `MldsaPkeyCtx` in `dst->data`. It then invokes `dctx->context.CopyFrom(sctx->context)`. On failure, the function returns `0` immediately without calling `Cleanup(dst)`.

This leak is practically reachable through `EVP_PKEY_CTX_dup`, which allocates a fresh destination context and invokes the algorithm `copy` hook. If that hook fails, `EVP_PKEY_CTX_dup` sets `ret->pmeth = nullptr` before returning `nullptr`, disabling `EvpPkeyCtx` destructor cleanup because the destructor only calls `pmeth->cleanup(this)` when `pmeth` is non-null. Therefore, the `dst->data` allocation created by `Init(dst)` becomes unreachable and leaked on this error path.

## Why This Is A Real Bug
The bug is not a theoretical ownership mismatch. It is a concrete heap leak on a reachable failure path:
- allocation of `dst->data` definitely occurs before the failing operation
- the failing branch definitely returns without freeing that allocation
- the normal outer cleanup path is explicitly disabled by `EVP_PKEY_CTX_dup` nulling `pmeth`

This produces a per-failure memory leak during ML-DSA context duplication under allocation or internal copy failure.

## Fix Requirement
On `CopyFrom` failure, `CopyContext` must clean up the partially initialized destination context before returning failure. The cleanup must release the allocated `MldsaPkeyCtx` and leave `dst` in a non-owning state.

## Patch Rationale
The correct fix is local to the failing branch in `CopyContext`: call `Cleanup(dst)` before returning `0`. This matches the ownership established by `Init(dst)`, restores error-path symmetry, and avoids relying on caller-side destruction behavior that is intentionally bypassed in `EVP_PKEY_CTX_dup` after copy failure.

## Residual Risk
None

## Patch
Patch: `017-copycontext-leaks-allocated-dst-context-on-copy-failure.patch`

```diff
diff --git a/crypto/evp/p_mldsa.cc b/crypto/evp/p_mldsa.cc
--- a/crypto/evp/p_mldsa.cc
+++ b/crypto/evp/p_mldsa.cc
@@ -329,7 +329,10 @@ static int CopyContext(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src) {
     return 0;
   }
   if (!dctx->context.CopyFrom(sctx->context)) {
+    // Release the destination context allocated by Init on copy failure.
+    Cleanup(dst);
     return 0;
   }
   return 1;
 }
```