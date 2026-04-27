# Zero-Length Device Path Stalls Iterator

## Classification

Invariant violation. Severity: low. Confidence: certain.

## Affected Locations

`library/std/src/sys/pal/uefi/helpers.rs:431`

## Summary

A malformed non-end UEFI device-path node with length `0` causes `DevicePathIterator` to stop making forward progress. The iterator advances by `DevicePathNode::length()`, so a zero-length node makes `next_node()` return the same pointer while `is_end()` remains false. Unbounded iteration can therefore loop forever.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

The caller constructs a `BorrowedDevicePath` over a malformed non-end device-path node whose encoded length is less than the UEFI device-path header size, specifically length `0`.

## Proof

`BorrowedDevicePath::iter` creates a `DevicePathIterator` from `DevicePathNode::new`.

`DevicePathIterator::next` calls:

```rust
let next_node = unsafe { cur_node.next_node() };
```

`DevicePathNode::next_node` advances the raw pointer by `self.length()`:

```rust
.add(self.length().into())
```

`DevicePathNode::length` directly reads the two-byte node length without validating that it is at least the 4-byte UEFI device-path header size.

For a malformed non-end node with length `0`, `.add(0)` returns the same pointer. Since the node is not an end node, `is_end()` remains false and the iterator stores the same node again. The next call repeats the same operation indefinitely.

An unbounded consumer such as:

```rust
for _ in borrowed_path.iter() {
    // ...
}
```

will receive the same node forever. The in-tree `path_best_match` logic in `library/std/src/sys/fs/uefi.rs:842` can also spin when both current malformed zero-length nodes compare equal.

## Why This Is A Real Bug

UEFI device paths can originate from firmware, drivers, or shell mappings, and malformed paths are possible at those trust boundaries. The iterator assumes the device-path invariant that every non-end node has at least the fixed header size, but the code does not enforce that invariant before pointer advancement.

Because progress depends entirely on `length()`, a zero-length non-end node violates the iterator progress guarantee and creates a denial-of-service style hang in any unbounded consumer.

## Fix Requirement

The iterator must reject or stop on malformed nodes whose length is smaller than `size_of::<device_path::Protocol>()`, the UEFI device-path header size.

## Patch Rationale

The patch treats undersized nodes as terminal for iteration.

It validates the initial node in `DevicePathIterator::new`, preventing iteration from starting on a malformed undersized non-end node. It also validates each computed `next_node` in `Iterator::next`, preventing the iterator from storing a malformed node and repeatedly yielding from an invalid or non-progressing path.

This preserves normal behavior for valid device paths while ensuring malformed zero-length or otherwise undersized nodes cannot stall iteration.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/uefi/helpers.rs b/library/std/src/sys/pal/uefi/helpers.rs
index 9db72db6067..28e8d10ed12 100644
--- a/library/std/src/sys/pal/uefi/helpers.rs
+++ b/library/std/src/sys/pal/uefi/helpers.rs
@@ -363,7 +363,11 @@ fn fmt(&self, f: &mut crate::fmt::Formatter<'_>) -> crate::fmt::Result {
 
 impl<'a> DevicePathIterator<'a> {
     const fn new(node: DevicePathNode<'a>) -> Self {
-        if node.is_end() { Self(None) } else { Self(Some(node)) }
+        if node.is_end() || node.length() < size_of::<device_path::Protocol>() as u16 {
+            Self(None)
+        } else {
+            Self(Some(node))
+        }
     }
 }
 
@@ -374,7 +378,13 @@ fn next(&mut self) -> Option<Self::Item> {
         let cur_node = self.0?;
 
         let next_node = unsafe { cur_node.next_node() };
-        self.0 = if next_node.is_end() { None } else { Some(next_node) };
+        self.0 = if next_node.is_end()
+            || next_node.length() < size_of::<device_path::Protocol>() as u16
+        {
+            None
+        } else {
+            Some(next_node)
+        };
 
         Some(cur_node)
     }
```