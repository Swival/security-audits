# Aborted pending response leaks heap allocation

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`src/runtime/server/HTMLBundle.rs:868`

## Summary

While an `HTMLBundle` route is in `State::Building`, each request allocates a `PendingResponse` on the heap and stores its raw pointer in `route.pending_responses`. If the client aborts before the build completes, `PendingResponse::on_aborted` removes that pointer from the vector but does not reconstruct or drop the boxed allocation. Because later cleanup only frees entries still present in the vector, repeated aborts leak heap memory until the server process can exhaust memory.

## Provenance

Verified from supplied source, reproducer summary, and patch.

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- An unauthenticated HTTP client can reach an `HTMLBundle` route.
- The route remains in `State::Building` long enough for clients to abort pending requests.
- Aborted connections invoke `PendingResponse::on_aborted`.

## Proof

In `State::Building`, `Route::on_any_request` allocates a pending response:

```rust
let pending = bun_core::heap::into_raw(Box::new(PendingResponse {
    method,
    resp,
    server: route.server.get(),
    route: this,
    is_response_pending: true,
}));
route.pending_responses.with_mut(|v| v.push(pending));
unsafe { RefCount::<Route>::ref_(this) };
resp.on_aborted(PendingResponse::on_aborted, pending);
```

On abort, `PendingResponse::on_aborted` finds and removes the matching raw pointer from `route.pending_responses`, then only releases the route reference:

```rust
v.remove(index);
true
...
unsafe { RefCount::<Route>::deref(route_ptr) };
```

It does not call `bun_core::heap::take(this)`, `drop`, or an equivalent `Box::from_raw` reclamation path for the removed `PendingResponse`.

The normal completion path in `resume_pending_responses` only frees pointers still present in the vector:

```rust
let pending = self.pending_responses.replace(Vec::new());
for pending_response_ptr in pending {
    let _drop = scopeguard::guard(pending_response_ptr, |p| {
        drop(unsafe { bun_core::heap::take(p) });
    });
}
```

Therefore, once an aborted entry is removed from the vector, it is no longer reachable by the normal cleanup path and its heap allocation is leaked.

## Why This Is A Real Bug

The allocation and ownership model is explicit: `PendingResponse` is created with `Box::new`, converted to a raw pointer with `bun_core::heap::into_raw`, and later must be reclaimed with `bun_core::heap::take` followed by `drop`.

The non-aborted path does that in `resume_pending_responses`. The aborted path removes the pointer from the only tracking vector before freeing it, making subsequent cleanup impossible. An unauthenticated remote client can repeatedly create and abort pending responses during a sufficiently long build, causing unbounded heap growth in the server process.

This is an attacker-triggered memory leak and practical denial of service.

## Fix Requirement

When `PendingResponse::on_aborted` successfully removes the pending pointer from `route.pending_responses`, it must reclaim the allocation exactly once by reconstructing and dropping the boxed `PendingResponse`. The `PendingResponse` destructor must remain responsible for releasing the route reference taken when the pending entry was created.

## Patch Rationale

The patch changes `on_aborted` to remove at most the matching pointer once, then immediately reclaim it:

```rust
if removed {
    drop(unsafe { bun_core::heap::take(this) });
}
```

This matches the allocation in `on_any_request` and the existing cleanup pattern in `resume_pending_responses`.

Dropping the `PendingResponse` also runs its `Drop` implementation, which clears response state as needed and releases the corresponding `Route` refcount. This removes the prior split cleanup behavior where `on_aborted` manually dereferenced the route but leaked the `PendingResponse` allocation.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/server/HTMLBundle.rs b/src/runtime/server/HTMLBundle.rs
index 619adb7530..0d833a328d 100644
--- a/src/runtime/server/HTMLBundle.rs
+++ b/src/runtime/server/HTMLBundle.rs
@@ -848,20 +848,17 @@ impl PendingResponse {
         // R-2: scope the `&mut Vec` to the find+remove only — `RefCount::deref`
         // can run `Route::drop` (which `get()`s `pending_responses`) and must
         // not overlap a live `with_mut` borrow.
-        loop {
-            let removed = route.pending_responses.with_mut(|v| {
-                if let Some(index) = v.iter().position(|&p| p == this) {
-                    v.remove(index);
-                    true
-                } else {
-                    false
-                }
-            });
-            if !removed {
-                break;
+        let removed = route.pending_responses.with_mut(|v| {
+            if let Some(index) = v.iter().position(|&p| p == this) {
+                v.remove(index);
+                true
+            } else {
+                false
             }
-            // SAFETY: matches the ref taken when this entry was pushed in on_any_request.
-            unsafe { RefCount::<Route>::deref(route_ptr) };
+        });
+        if removed {
+            // SAFETY: matches the heap allocation in on_any_request; Drop releases the route ref.
+            drop(unsafe { bun_core::heap::take(this) });
         }
     }
 }
```