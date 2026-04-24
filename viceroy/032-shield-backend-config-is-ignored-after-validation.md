# Shield backend config is ignored after validation

## Classification
- Type: logic error
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/wiggle_abi/shielding.rs:75`

## Summary
`backend_for_shield` accepts guest-supplied `shield_backend_options` and validated `shield_backend_config`, but on the successful path it registers a `Backend` without applying any supported shield settings. As reproduced, API-exposed values such as `cache_key` and `first_byte_timeout_ms` are silently discarded, so the returned backend behaves as though defaults were used.

## Provenance
- Verified from the supplied reproducer and source review
- Reference: Swival Security Scanner, `https://swival.dev`

## Preconditions
- Caller invokes `backend_for_shield` with non-default shield config or option bits

## Proof
- In `src/wiggle_abi/shielding.rs:75`, `backend_for_shield` reads `shield_backend_options` and `shield_backend_config`.
- The function validates reserved bits and conditionally validates the optional `cache_key` string.
- After validation, the created `Backend` does not consume the validated shield config for any supported field.
- Reproduction confirms the practical effect: non-default `cache_key` and `first_byte_timeout_ms` are accepted, a backend name is returned, and the resulting backend still behaves as default.
- The alternate component implementation rejects shield backend options as unsupported in `src/component/compute/shielding.rs:83`, confirming the wiggle path is inconsistent and misleading.

## Why This Is A Real Bug
The function signals success and returns a registered backend identifier after validating caller input, which implies the requested shield configuration was honored. Instead, supported guest-visible settings are ignored. This is a silent misconfiguration: callers cannot distinguish success-with-defaults from success-with-requested-settings, and runtime behavior diverges from validated input on every reachable successful call using non-default shield options.

## Fix Requirement
Either:
- map validated shield settings into the constructed `Backend`, or
- reject unsupported non-default shield settings so callers do not receive a false-success result

## Patch Rationale
The patch should make the wiggle shielding path match actual capability. If `cache_key` and `first_byte_timeout_ms` are unsupported here, fail closed on non-default values instead of validating and discarding them. If they are intended to be supported, wire them into backend construction so successful calls preserve caller intent.

## Residual Risk
None

## Patch
- `032-shield-backend-config-is-ignored-after-validation.patch` rejects unsupported non-default shield backend configuration in the wiggle path instead of silently accepting it.
- This removes the false-success behavior and aligns the API outcome with effective backend behavior.
- The patch is consistent with the component implementation’s existing unsupported-options handling in `src/component/compute/shielding.rs:83`.