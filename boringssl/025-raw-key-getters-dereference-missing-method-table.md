# Raw key getters dereference missing method table

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `crypto/evp/evp.cc:241`
- `crypto/evp/evp.cc:250`
- `crypto/evp/evp.cc:259`
- `crypto/evp/evp.cc:268`
- `crypto/evp/evp.cc:278`

## Summary
Several raw key accessor and TLS encoded-point helpers dereference `impl->ameth` without verifying that the `EVP_PKEY` instance has an attached method table. An `EVP_PKEY` created by `EVP_PKEY_new()` starts empty, and `EVP_PKEY_set_type` can also reset a previously populated key back to that same state before rejecting an unsupported type. Calling these helpers on such an object crashes the process instead of returning an unsupported-operation error.

## Provenance
- Verified from the supplied reproducer and code inspection
- Reproduced against the committed tree with a minimal crashing program
- Scanner: [Swival Security Scanner](https://swival.dev)

## Preconditions
- Caller passes an `EVP_PKEY` whose internal `ameth` is `nullptr`
- This occurs for a freshly allocated key from `EVP_PKEY_new()`
- This also occurs after `EVP_PKEY_set_type` clears an existing key and then rejects an unsupported type

## Proof
`EVP_PKEY_get_raw_private_key`, `EVP_PKEY_get_private_seed`, `EVP_PKEY_get_raw_public_key`, `EVP_PKEY_set1_tls_encodedpoint`, and `EVP_PKEY_get1_tls_encodedpoint` all dispatch through `impl->ameth->...` without checking whether `impl->ameth` exists.

A minimal reproducer:
```c
EVP_PKEY *pkey = EVP_PKEY_new();
size_t len = 0;
EVP_PKEY_get_raw_private_key(pkey, NULL, &len);
```

Observed result: process terminates with `Segmentation fault: 11` and exit code `139`, before any unsupported-operation error is returned.

The state is also reachable from a previously valid key because `EVP_PKEY_set_type` clears the object with `evp_pkey_set0(impl, nullptr, nullptr)` before rejecting unsupported types, and the existing test at `crypto/evp/evp_extra_test.cc:1304` shows the object remains reset afterward.

## Why This Is A Real Bug
This is a direct null-pointer dereference on a public API path. The empty-key state is intentionally constructible through `EVP_PKEY_new()` and recoverable through normal API usage after a failed `EVP_PKEY_set_type` call. Because the helpers crash before reporting an error, any consumer that passes an empty or reset key can trigger a reliable process-level denial of service.

## Fix Requirement
Add guards for both the internal key object and its method table before any `impl->ameth->...` dispatch in the affected helpers, and return the existing unsupported-operation error path when either is absent.

## Patch Rationale
The patch adds explicit `impl == nullptr || impl->ameth == nullptr` checks in each affected helper and routes those cases to the same unsupported-operation handling already used when the specific method callback is absent. This preserves existing API semantics for unsupported operations while eliminating the null dereference.

## Residual Risk
None

## Patch
- Patch file: `025-raw-key-getters-dereference-missing-method-table.patch`
- Change: guard `impl` and `impl->ameth` before dereferencing the method table in the five affected helpers in `crypto/evp/evp.cc`
- Result: empty or reset `EVP_PKEY` inputs now fail cleanly with an unsupported-operation error instead of crashing