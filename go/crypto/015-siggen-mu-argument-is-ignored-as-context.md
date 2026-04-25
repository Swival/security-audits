# sigGen mu Argument Is Parsed As context

## Classification

Logic error; medium severity; confidence: certain.

## Affected Locations

`src/crypto/internal/fips140test/acvp_fips140v1.26_test.go:57`

## Summary

The `ML-DSA-*/sigGen` ACVP handler declares argument order as secret key, message, randomizer, `mu`, context, but parses `args[3]` as context and `args[4]` as `mu`. Valid external-`mu` requests are rejected or sign the wrong bytes.

## Provenance

Verified from the supplied finding and reproducer. Scanner provenance: https://swival.dev

## Preconditions

`sigGen` is called with five arguments in the declared order, with non-empty external `mu` at `args[3]` and optional context at `args[4]`.

## Proof

The handler declares `requiredArgs` in the order secret key, message, randomizer, `mu`, context. The wrapper dispatch reaches the handler through `src/crypto/internal/fips140test/acvp_test.go:351`, validates only argument count at `src/crypto/internal/fips140test/acvp_test.go:356`, and invokes the handler at `src/crypto/internal/fips140test/acvp_test.go:360`.

With `ML-DSA-44/sigGen`, empty message/randomizer, a non-empty 64-byte `mu` at `args[3]`, and empty context at `args[4]`, the handler treats the `mu` as context and treats the empty context as `mu`. `haveMu` becomes false, so the valid external-`mu` request falls into the unsupported-arguments path. If `args[4]` is non-empty and 64 bytes, the external-`mu` signing path signs `args[4]` instead of caller-supplied `args[3]`.

## Why This Is A Real Bug

The parser contradicts the command’s own declared argument contract. ACVP callers using the documented order cannot reliably exercise external-`mu` signing: valid inputs may be rejected, and accepted inputs may produce signatures over context bytes instead of the provided `mu`.

## Fix Requirement

Parse `mu` from `args[3]` and parse context from `args[4]`.

## Patch Rationale

The patch swaps the two assignments so the implementation matches the declared `requiredArgs` order. This preserves existing control flow and signing behavior while correcting the source bytes used for `haveMu`, external-`mu` validation, and `SignExternalMu*` calls.

## Residual Risk

None

## Patch

`015-siggen-mu-argument-is-ignored-as-context.patch`