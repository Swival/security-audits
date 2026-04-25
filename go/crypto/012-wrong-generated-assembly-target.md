# Wrong Generated Assembly Target

## Classification

Logic error, low severity. Confidence: certain.

## Affected Locations

`src/crypto/internal/fips140/aes/_asm/standard/aes_amd64.go:46`

## Summary

The AES amd64 generator writes assembly to `../../aes_amd64.s` but post-processes `../../asm_amd64.s`. As a result, `go generate` targets one file and the Unicode-dot cleanup targets a different file.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Running `go generate` for `src/crypto/internal/fips140/aes/_asm/standard/aes_amd64.go`.

## Proof

The generator directive emits Avo output to `../../aes_amd64.s`, while `main` calls `removePeskyUnicodeDot` on `../../asm_amd64.s`.

The helper then reads the supplied target via `os.ReadFile(target)` and panics on failure. In the committed tree, `src/crypto/internal/fips140/aes/aes_amd64.s` exists, but `src/crypto/internal/fips140/aes/asm_amd64.s` does not.

Therefore, a successful generator run reaches the cleanup step and attempts to process a non-existent or unrelated file. If `asm_amd64.s` exists locally, the newly generated `aes_amd64.s` remains unprocessed.

## Why This Is A Real Bug

The generator and cleanup helper disagree on the generated assembly path. This violates the helper’s intended invariant that generated internal `TEXT` symbols in the target assembly are normalized after generation.

The committed generated file already contains stripped internal symbols such as `TEXT _expand_key_128<>(SB)`, confirming that `aes_amd64.s` is the intended cleanup target.

## Fix Requirement

Pass `../../aes_amd64.s` to `removePeskyUnicodeDot`.

## Patch Rationale

The patch changes the cleanup target to match the Avo output target. This makes regeneration deterministic and ensures the post-processing step applies to the file that was just generated.

## Residual Risk

None

## Patch

`012-wrong-generated-assembly-target.patch`