# Movable Self-Referential List Pointer

## Classification

Invariant violation, high severity.

## Affected Locations

`library/std/src/sys/pal/sgx/waitqueue/unsafe_list.rs:42`

## Summary

`UnsafeList<T>` stores `head_tail` as a raw `NonNull` pointer to its own embedded `head_tail_entry`. Because `UnsafeList<T>` remains movable, moving an initialized list leaves `head_tail` pointing at the old object location. Later list operations dereference that stale self-pointer, violating the list invariant and enabling undefined behavior.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

An initialized `UnsafeList<T>` is moved and then used again.

## Proof

`UnsafeList::init()` initializes the self-reference:

```rust
self.head_tail =
    unsafe { NonNull::new_unchecked(self.head_tail_entry.as_mut().unwrap()) };
```

After any ordinary Rust move of the initialized `UnsafeList<T>`, the embedded `head_tail_entry` resides at the new object address, but `head_tail` still contains the old address.

A reproduced path is:

```rust
let mut list = UnsafeList::new();
unsafe { list.pop(); } // calls init()
let moved = list;      // ordinary move
moved.is_empty();      // dereferences stale head_tail
```

The propagation path is:

- `pop()` calls `init()` at `library/std/src/sys/pal/sgx/waitqueue/unsafe_list.rs:106`
- `init()` makes `head_tail` point into the original object at `library/std/src/sys/pal/sgx/waitqueue/unsafe_list.rs:42`
- after a move, `is_empty()` dereferences the stale pointer at `library/std/src/sys/pal/sgx/waitqueue/unsafe_list.rs:52`

A small runtime proof of concept copied from the implementation confirmed that, after moving, `head_tail` still pointed to the old stack address while the embedded `head_tail_entry` lived at a new address. `is_empty()` then used the old address.

## Why This Is A Real Bug

The type comment acknowledges `UnsafeList<T>` is self-referential, but the type does not enforce immovability with `Pin`, `PhantomPinned`, or equivalent constraints.

Current SGX `Mutex` and `Condvar` wrappers appear to box or pin their `WaitVariable` storage, including at:

- `library/std/src/sys/sync/mutex/sgx.rs:5`
- `library/std/src/sys/sync/mutex/sgx.rs:16`
- `library/std/src/sys/sync/condvar/sgx.rs:6`
- `library/std/src/sys/sync/condvar/sgx.rs:16`

That wrapper behavior does not repair the invariant of `UnsafeList<T>` itself. The type can still be initialized, moved, and then used through its own public methods, leaving its internal self-reference stale.

## Fix Requirement

The implementation must ensure that `UnsafeList<T>` operations never dereference a stale self-referential `head_tail` pointer after the list has moved.

Acceptable fixes include:

- make `UnsafeList<T>` immovable using `Pin` or `PhantomPinned`; or
- avoid storing a self-referential pointer; or
- repair the cached self-reference before operations that may observe or mutate the list.

## Patch Rationale

The patch repairs the self-referential invariant inside `init()` when `head_tail_entry` already exists.

If the current embedded `head_tail_entry` address differs from the cached `head_tail`, the patch:

- computes the new `head_tail` pointer from `self.head_tail_entry.as_mut().unwrap()`;
- replaces the stale `self.head_tail`;
- rewrites neighboring list links that still reference the old sentinel pointer;
- handles both empty-list sentinel links and non-empty list neighbor links.

The patch also changes `is_empty()` to avoid dereferencing `self.head_tail` directly. It derives the current sentinel address from `head_tail_entry` and reads links from the embedded entry, so a moved list can be checked without first dereferencing the stale cached pointer.

Finally, `remove()` now calls `init()` before checking emptiness, ensuring the sentinel pointer is repaired before removal logic uses list links.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/sgx/waitqueue/unsafe_list.rs b/library/std/src/sys/pal/sgx/waitqueue/unsafe_list.rs
index c736cab576e..dbe7c5ce3c1 100644
--- a/library/std/src/sys/pal/sgx/waitqueue/unsafe_list.rs
+++ b/library/std/src/sys/pal/sgx/waitqueue/unsafe_list.rs
@@ -44,18 +44,35 @@ unsafe fn init(&mut self) {
             // SAFETY: `self.head_tail` must meet all requirements for a mutable reference.
             unsafe { self.head_tail.as_mut() }.next = self.head_tail;
             unsafe { self.head_tail.as_mut() }.prev = self.head_tail;
+        } else {
+            let mut head_tail =
+                unsafe { NonNull::new_unchecked(self.head_tail_entry.as_mut().unwrap()) };
+            if self.head_tail != head_tail {
+                let old_head_tail = mem::replace(&mut self.head_tail, head_tail);
+                let head_tail_entry = unsafe { head_tail.as_mut() };
+                if head_tail_entry.next == old_head_tail {
+                    head_tail_entry.next = head_tail;
+                } else {
+                    unsafe { head_tail_entry.next.as_mut() }.prev = head_tail;
+                }
+                if head_tail_entry.prev == old_head_tail {
+                    head_tail_entry.prev = head_tail;
+                } else {
+                    unsafe { head_tail_entry.prev.as_mut() }.next = head_tail;
+                }
+            }
         }
     }
 
     pub fn is_empty(&self) -> bool {
-        if self.head_tail_entry.is_some() {
-            let first = unsafe { self.head_tail.as_ref() }.next;
-            if first == self.head_tail {
+        if let Some(head_tail_entry) = self.head_tail_entry.as_ref() {
+            let head_tail = NonNull::from(head_tail_entry);
+            let first = head_tail_entry.next;
+            if first == head_tail || first == self.head_tail {
                 // ,-------> /---------\ next ---,
                 // |         |head_tail|         |
                 // `--- prev \---------/ <-------`
-                // SAFETY: `self.head_tail` must meet all requirements for a reference.
-                unsafe { rtassert!(self.head_tail.as_ref().prev == first) };
+                rtassert!(head_tail_entry.prev == first);
                 true
             } else {
                 false
@@ -135,6 +152,7 @@ pub unsafe fn pop<'a>(&mut self) -> Option<&'a T> {
     /// The caller must ensure that `entry` has been pushed onto `self`
     /// prior to this call and has not moved since then.
     pub unsafe fn remove(&mut self, entry: &mut UnsafeListEntry<T>) {
+        unsafe { self.init() };
         rtassert!(!self.is_empty());
         // BEFORE:
         //     /----\ next ---> /-----\ next ---> /----\
```