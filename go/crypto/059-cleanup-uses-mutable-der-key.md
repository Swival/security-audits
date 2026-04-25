# Cleanup Uses Mutable DER Key

## Classification

Resource lifecycle bug; severity low; confidence certain.

## Affected Locations

`src/crypto/tls/cache.go:30`

## Summary

Certificate cache cleanup recomputes `string(der)` from a caller-owned mutable DER slice instead of using the immutable key originally used for insertion. If the caller mutates the DER bytes before cleanup runs, cleanup misses the original cache entry and leaves a stale `sync.Map` entry.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Caller mutates the DER slice after the certificate is cached and before the cleanup callback runs.

## Proof

`newCert` stores cache entries under `string(der)`, then registers cleanup closures that call `CompareAndDelete(string(der), ...)`.

Although the cleanup callback receives a captured parameter derived from `any(string(der))`, that parameter is ignored. The cleanup instead recomputes `string(der)` from the mutable input slice.

If `der` changes after `Store(string(der), wp)` but before the certificate becomes unreachable and cleanup executes, `CompareAndDelete` uses the mutated key and misses the original entry. The stale cache entry remains with the original DER string key and a dead weak pointer.

This path is practically reachable through `ParseSessionState`: it accepts caller-owned `data []byte`, `unmarshalCertificate` stores certificate slices as subslices of that data, and `ParseSessionState` passes them to `globalCertCache.newCert`.

## Why This Is A Real Bug

The cache key used for insertion and the cache key used for cleanup can diverge for the same logical certificate lifetime. That breaks the intended lifecycle invariant that dead cached certificates remove their corresponding cache entries.

The impact is bounded to resource retention: the stale cache value is weak and does not appear to retain the parsed certificate itself, but the original DER string key and dead weak-pointer entry can persist indefinitely unless the same original DER key is later processed and replaced or deleted.

## Fix Requirement

Capture `key := string(der)` once in `newCert` and use that immutable key for all cache operations and cleanup callbacks.

## Patch Rationale

The patch makes the cache key stable across insertion, lookup, and cleanup. Since Go strings are immutable and `string(der)` copies the bytes, capturing the key once prevents later caller mutation of `der` from changing cleanup behavior.

## Residual Risk

None

## Patch

`059-cleanup-uses-mutable-der-key.patch`