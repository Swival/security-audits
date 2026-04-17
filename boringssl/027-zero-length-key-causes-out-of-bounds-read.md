# Zero-length key causes out-of-bounds read

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `crypto/rc4/rc4.cc:36`

## Summary
`RC4_set_key` reads `key[0]` even when called with `len == 0`. This violates the key-length/index invariant and causes an immediate out-of-bounds read on the first loop iteration for direct callers of the low-level API.

## Provenance
- Verified from the reported location in `crypto/rc4/rc4.cc:36`
- Reproduced with AddressSanitizer using a direct call to `RC4_set_key(&sched, 0, buf + 1)`
- Scanner source: https://swival.dev

## Preconditions
- `RC4_set_key` is called with `len == 0`

## Proof
In `RC4_set_key`, `id1` is initialized to `0`. The key scheduling loop then evaluates `key[id1]` before any condition can make that access safe for a zero-length key. When `len == 0`, the wraparound check `if (++id1 == len)` never establishes a valid index domain, so the first iteration dereferences `key[0]` despite no bytes being available.

This was reproduced under ASan with a 1-byte heap allocation and the pointer advanced by one byte so that `key[0]` is immediately out of bounds. ASan reports a heap-buffer-overflow read in `RC4_set_key`, confirming the access occurs in practice.

## Why This Is A Real Bug
The fault is on the direct low-level API, independent of higher-level EVP validation. While EVP rejects zero-length RC4 keys on the tested path, `RC4_set_key` itself remains callable with attacker-controlled `len` and `key`. A direct caller can therefore trigger a memory-safety violation: either an immediate crash when the pointer is invalid or boundary-adjacent, or unintended memory consumption as key material when the pointer remains mapped.

## Fix Requirement
Reject `len == 0` before entering the key scheduling loop, or otherwise return without reading from `key`.

## Patch Rationale
The patch adds an explicit zero-length guard in `RC4_set_key` so the function does not dereference `key` when no key bytes exist. This directly enforces the missing invariant at the API boundary and eliminates the out-of-bounds read without changing behavior for valid key lengths.

## Residual Risk
None

## Patch
- Patch file: `027-zero-length-key-causes-out-of-bounds-read.patch`
- Change: add a `len == 0` early return in `crypto/rc4/rc4.cc` before any use of `key`
- Effect: prevents the first-iteration `key[0]` read and preserves existing behavior for all non-zero key lengths