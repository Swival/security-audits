# Timestamp-Keyed Replay Cache Forgets Same-Second Ciphertexts

## Classification

security_control_failure, high severity, certain confidence

## Affected Locations

- `src/pqconnect/pqcserver.py:197`

## Summary

`PQCServer.remember_mceliece_ct` stored observed McEliece ciphertexts in `_seen_mceliece_cts` using `int(time())` as the dictionary key. When two distinct valid 0-RTT handshakes completed during the same monotonic second, the later ciphertext overwrote the earlier ciphertext. The overwritten ciphertext was then absent from `is_mceliece_ct_seen`, allowing replay of a previously accepted 0-RTT handshake ciphertext.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

- The server completes at least two distinct valid 0-RTT handshakes in the same monotonic second.
- An attacker has captured one of the valid handshake packets whose McEliece ciphertext was later overwritten.

## Proof

- The replay cache was declared as `Dict[int, bytes]`, mapping timestamp to ciphertext.
- `remember_mceliece_ct` computed `now = int(time())` and stored `self._seen_mceliece_cts[now] = mceliece_ct`.
- With fixed `time()` returning the same second, storing `b'first-valid-c0'` produced `{12345: b'first-valid-c0'}`.
- Storing `b'second-valid-c0'` in the same second produced `{12345: b'second-valid-c0'}`.
- After the overwrite, `is_mceliece_ct_seen(b'first-valid-c0')` returned `False`.
- The network path is reachable because UDP packets beginning with `INITIATION_MSG` are queued by `TunDevice` and passed to `PQCServer.complete_handshake`.
- `shake_hands` checks `is_mceliece_ct_seen` before `complete_handshake_0rtt`, then records `c0` only after successful validation, so an overwritten valid `c0` can be replayed and accepted.

## Why This Is A Real Bug

This is the replay-protection control for 0-RTT handshakes. Its purpose is to remember successful McEliece ciphertexts during the relevant key-validity window and reject repeats. Keying the cache by second-level timestamps makes entries collide under normal concurrent or burst handshake traffic. A later valid handshake in the same second deletes the earlier replay marker, causing the control to fail open for the earlier captured ciphertext.

## Fix Requirement

Key the replay cache by ciphertext and store the observation timestamp as the value. Replay checks must test dictionary key membership for the ciphertext, and cleanup must expire entries by their stored timestamp.

## Patch Rationale

The patch changes `_seen_mceliece_cts` from `Dict[int, bytes]` to `Dict[bytes, int]`. This makes each ciphertext the unique cache key, preventing same-second overwrites between distinct ciphertexts. It also changes `is_mceliece_ct_seen` to O(1) key membership and updates cleanup to iterate over `(ciphertext, timestamp)` pairs, deleting expired ciphertext keys.

## Residual Risk

None

## Patch

```diff
diff --git a/src/pqconnect/pqcserver.py b/src/pqconnect/pqcserver.py
index 2a00492..451133f 100644
--- a/src/pqconnect/pqcserver.py
+++ b/src/pqconnect/pqcserver.py
@@ -99,12 +99,7 @@ class PQCServer:
         # ciphertexts from handshakes sent during the current ephemeral key
         # validity period. This gets cleaned periodically by a cleanup routine.
 
-        self._seen_mceliece_cts: Dict[int, bytes] = dict()
-
-        # XXX: checking for seen ct's means scanning whole dict. Probably
-        # should reverse this, so the forgetting thread scans all entries every
-        # 30 seconds to remove ones with old timestamps, and checking for
-        # replays is O(1)
+        self._seen_mceliece_cts: Dict[bytes, int] = dict()
 
         self._forget_old_mceliece_cts_thread = Thread(
             target=self._forget_old_mceliece_cts
@@ -182,10 +177,10 @@ class PQCServer:
         recently observed ciphertext values
 
         """
-        return mceliece_ct in self._seen_mceliece_cts.values()
+        return mceliece_ct in self._seen_mceliece_cts
 
     def remember_mceliece_ct(self, mceliece_ct: bytes) -> None:
-        """Stores a (timestamp,mceliece ciphertext) record from a successful
+        """Stores a (mceliece ciphertext,timestamp) record from a successful
         handshake for future replay checks
 
         """
@@ -195,7 +190,7 @@ class PQCServer:
                     "Cannot add the same mceliece ciphertext twice"
                 )
             now = int(time())
-            self._seen_mceliece_cts[now] = mceliece_ct
+            self._seen_mceliece_cts[mceliece_ct] = now
 
     def _forget_old_mceliece_cts(self) -> None:
         """Remove old handshake mceliece ciphertexts"""
@@ -205,12 +200,12 @@ class PQCServer:
             with self._mut:
                 expired = []
                 old = time() - EPOCH_TIMEOUT_SECONDS
-                for ts in self._seen_mceliece_cts.keys():
+                for ct, ts in self._seen_mceliece_cts.items():
                     if ts <= old:
-                        expired.append(ts)
+                        expired.append(ct)
 
-                for ts in expired:
-                    del self._seen_mceliece_cts[ts]
+                for ct in expired:
+                    del self._seen_mceliece_cts[ct]
 
     def add_new_connection(
         self, session: TunnelSession, addr: Tuple[str, int]
```