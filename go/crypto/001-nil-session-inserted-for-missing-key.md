# Nil Session Inserted For Missing Key

## Classification

Invariant violation, low severity. Confidence: certain.

## Affected Locations

`src/crypto/tls/common.go:1689`

## Summary

`lruSessionCache.Put` inserts a nil `*ClientSessionState` when called as `Put(key, nil)` for a missing key. This violates the documented `ClientSessionCache.Put` contract that nil state removes an entry, and causes later `Get(key)` to return `(nil, true)`.

## Provenance

Verified from the provided reproducer and patch context. Originally reported by Swival Security Scanner: https://swival.dev

## Preconditions

- LRU client session cache is empty, or the target key is absent.
- Caller invokes `Put(key, nil)`.

## Proof

- `ClientSessionCache.Put` documents that nil `*ClientSessionState` should remove the cache entry.
- `lruSessionCache.Put` only handles nil removal in the existing-key branch.
- For an absent key, `cs == nil` falls through to the insert path.
- The cache constructs `lruSessionCacheEntry{sessionKey, cs}` and stores it in the list and map.
- A later `Get(key)` finds the map entry and returns `entry.state, true`, producing `(nil, true)`.
- On a full cache, absent-key nil `Put` can also evict a valid LRU entry before inserting the nil entry.

## Why This Is A Real Bug

The public cache contract requires nil `Put` to remove an entry. Returning `ok == true` for a nil session contradicts that invariant and leaves unusable entries consuming cache capacity. The behavior is reproducible with `tls.NewLRUClientSessionCache(1)`, `Put("k", nil)`, then `Get("k")`.

## Fix Requirement

If `cs == nil` and `sessionKey` is absent, `Put` must return without inserting or evicting anything.

## Patch Rationale

The patch adds an early return for nil session state after the existing-key removal path is checked. This preserves removal semantics for present keys and prevents nil session insertion for absent keys. It also avoids unnecessary LRU eviction when the cache is full.

## Residual Risk

None

## Patch

`001-nil-session-inserted-for-missing-key.patch`