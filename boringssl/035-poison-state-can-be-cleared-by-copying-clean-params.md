# Poison State Cleared by Clean Param Copy

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `crypto/x509/x509_vpm.cc:137`

## Summary
A poisoned `X509_VERIFY_PARAM` can be made clean again by copying from a non-poisoned source. `x509_verify_param_copy` overwrites `dest->poison` with `src->poison`, so a prior invalid identity-setting API misuse is forgotten. This breaks the intended fail-closed behavior where later verification should surface `INVALID_CALL`.

## Provenance
- Verified finding reproduced from the supplied report
- Source analysis and patch prepared against `crypto/x509/x509_vpm.cc`
- Reference: https://swival.dev

## Preconditions
- Destination `X509_VERIFY_PARAM` is already poisoned
- Source `X509_VERIFY_PARAM` has `poison == 0`
- Code later copies or inherits parameters via `X509_VERIFY_PARAM_set1` or `X509_VERIFY_PARAM_inherit`

## Proof
Invalid inputs to `X509_VERIFY_PARAM_set1_host`, `X509_VERIFY_PARAM_add1_host`, `X509_VERIFY_PARAM_set1_email`, or `X509_VERIFY_PARAM_set1_ip` set `dest->poison = 1`. Later, `X509_VERIFY_PARAM_inherit` or `X509_VERIFY_PARAM_set1` reaches `x509_verify_param_copy`, which executes `dest->poison = src->poison` at `crypto/x509/x509_vpm.cc:137`. When `src` is clean, this clears the poisoned destination. Subsequent verification no longer trips the `check_id`-driven `INVALID_CALL` path, so verification can proceed without the fail-closed marker that should persist after invalid API misuse.

## Why This Is A Real Bug
The poison bit is a sticky invalid-state marker. Clearing it by copying unrelated clean parameters violates monotonicity of that state. This is security-relevant, not cosmetic: several invalid identity setters fail before installing any replacement constraint, so once poison is cleared, later verification may run without the expected hostname, email, or IP constraint and without the compensating `INVALID_CALL` failure.

## Fix Requirement
Preserve poison monotonically during copies. Replace the direct assignment with an OR so a poisoned destination remains poisoned even when the source is clean.

## Patch Rationale
The minimal safe fix is to make `poison` sticky in `x509_verify_param_copy`:
- old behavior: `dest->poison = src->poison`
- new behavior: `dest->poison |= src->poison`

This matches the intended semantics of poison as a latched error state and prevents later copy or inherit operations from erasing prior invalid API misuse.

## Residual Risk
None

## Patch
Patched in `035-poison-state-can-be-cleared-by-copying-clean-params.patch` by changing `crypto/x509/x509_vpm.cc:137` to preserve poison monotonically with `dest->poison |= src->poison`.