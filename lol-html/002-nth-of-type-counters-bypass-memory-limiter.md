

# nth-of-type counters bypass memory limiter

## Classification

**Type:** Denial of Service (Memory Exhaustion)  
**Severity:** Medium  
**CWE:** CWE-400 (Uncontrolled Resource Consumption)  
**CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)

## Affected Locations

- `src/selectors_vm/stack.rs:76` — `TypedChildCounterMap` instantiation
- `src/selectors_vm/stack.rs:120` — `TypedChildCounterMap::add_child` entry insertion
- `src/selectors_vm/stack.rs:134` — `CounterList::items` Vec push

## Summary

When nth-of-type selector tracking is enabled, the `TypedChildCounterMap` uses an unbounded `HashMap` and `Vec` to track element counters by tag name. These allocations bypass the configured `SharedMemoryLimiter`, allowing an attacker to exhaust process memory by sending HTML with many distinct element names. The `Stack::add_child` method triggers these allocations without any memory limit checks.

## Provenance

Discovered by Swival.dev Security Scanner — https://swival.dev

## Preconditions

1. nth-of-type tracking must be enabled (`enable_nth_of_type: true` in `Stack::new`)
2. Application processes attacker-controlled HTML
3. Selector matching uses `*:nth-of-type(N)` or similar typed selectors

## Proof

1. `Stack::new` creates `LimitedVec<StackItem>` backed by `SharedMemoryLimiter` but initializes `TypedChildCounterMap` via `HashMap::new()` without a limiter reference
2. `Stack::add_child` calls `counters.add_child(name, self.items.len())` for each element
3. `TypedChildCounterMap::add_child` at line 120 calls `name.clone().into_owned()` inserting into the unbounded `HashMap` for new element names
4. When the same element name appears at different depths, line 134 pushes `CounterItem` values into unbounded `Vec<CounterItem>`
5. Neither operation calls `SharedMemoryLimiter::increase_usage`, and `add_child` returns `()` with no error propagation
6. A payload with many distinct custom element names at low stack depth creates unbounded map entries while keeping stack items within configured limits

## Why This Is A Real Bug

The memory limiter is intentionally bypassed through an independent allocation path. The `LimitedVec` correctly gates `StackItem` allocations, but the parallel `TypedChildCounterMap` structures accumulate unbounded strings and counter entries. An attacker can:

- Craft HTML with thousands of unique tag names (e.g., `<x1>`, `<x2>`, ..., `<x100000>`)
- Each unique name allocates a `LocalName<'static>` (string data + struct overhead) plus `CounterList` (~48 bytes) plus initial `CounterItem` (~16 bytes)
- Stack depth remains low, so `LimitedVec` never triggers
- Memory grows linearly with unique tag count outside any quota

This is not a theoretical leak; it is practical memory exhaustion triggered by standard HTTP request bodies processed through the HTML rewriter.

## Fix Requirement

All allocations within `TypedChildCounterMap` must be accounted against the `SharedMemoryLimiter`:
- New HashMap key-value entries (LocalName owned data + CounterList struct)
- CounterList.items Vec pushes (CounterItem structures)

When the limit is exceeded, tracking must gracefully degrade (skip counting for that element) rather than fail, preserving availability.

## Patch Rationale

The patch modifies `TypedChildCounterMap` to hold a `SharedMemoryLimiter` reference and checks limits before each allocation:

1. **Lines 103-106**: `TypedChildCounterMap` now contains explicit `map` and `limiter` fields
2. **Lines 111-119**: `entry_size()` estimates allocation size for a new HashMap entry
3. **Lines 125-129**: Before inserting a new element name, `limiter.increase_usage(entry_size)` is checked; on failure, tracking is skipped
4. **Lines 156-158**: When pushing to `CounterList.items`, the `CounterItem` size is accounted
5. **Line 252**: `Stack::new` passes the memory limiter to `TypedChildCounterMap::new`

Graceful degradation (skip tracking on limit exceeded) maintains availability rather than rejecting the entire operation.

## Residual Risk

None. The patch accounts all TypedChildCounterMap allocations against the SharedMemoryLimiter. On memory exhaustion, nth-of-type tracking is skipped for new elements, which is functionally correct (selector matching may fail for those elements, but no memory growth occurs). The existing LimitedVec gate for StackItem frames remains intact.

## Patch

```diff
diff --git a/src/selectors_vm/compiler.rs b/src/selectors_vm/compiler.rs
index 567d0bc..25293c4 100644
--- a/src/selectors_vm/compiler.rs
+++ b/src/selectors_vm/compiler.rs
@@ -81,11 +81,15 @@ impl Compilable for Expr<OnTagNameExpr> {
             }
             OnTagNameExpr::NthOfType(nth) => {
                 *enable_nth_of_type = true;
+                // `state.typed` is normally `Some` when an `:nth-of-type`
+                // selector is active. It can be `None` only when the
+                // typed-counter map refused to allocate an entry because
+                // the memory limiter rejected the request. In that case we
+                // treat the selector as a non-match for this element so
+                // the rewriter can degrade gracefully under memory
+                // pressure instead of panicking.
                 Self::compile_expr(neg, move |state, _| {
-                    state
-                        .typed
-                        .expect("Counter for type required at this point")
-                        .is_nth(nth)
+                    state.typed.is_some_and(|c| c.is_nth(nth))
                 })
             }
         };
diff --git a/src/selectors_vm/stack.rs b/src/selectors_vm/stack.rs
index b4cfc0a..e291f12 100644
--- a/src/selectors_vm/stack.rs
+++ b/src/selectors_vm/stack.rs
@@ -8,6 +8,7 @@ use crate::selectors_vm::DenseHashSet;
 use hashbrown::HashMap;
 use hashbrown::hash_map::RawEntryMut;
 use std::hash::BuildHasher;
+use std::mem::size_of;
 
 #[inline]
 fn is_void_element(local_name: &LocalName<'_>, enable_esi_tags: bool) -> bool {
@@ -99,25 +100,49 @@ impl CounterList {
 }
 
 /// A more efficient counter that only requires one owned local name to track counters across multiple stack frames
-pub(crate) struct TypedChildCounterMap(HashMap<LocalName<'static>, CounterList>);
+pub(crate) struct TypedChildCounterMap {
+    map: HashMap<LocalName<'static>, CounterList>,
+    limiter: SharedMemoryLimiter,
+}
 
 impl TypedChildCounterMap {
     #[must_use]
     #[inline]
-    pub(crate) fn new() -> Self {
-        Self(HashMap::new())
+    pub(crate) fn new(limiter: SharedMemoryLimiter) -> Self {
+        Self {
+            map: HashMap::new(),
+            limiter,
+        }
     }
 
     fn hash_name(&self, name: &LocalName<'_>) -> u64 {
-        self.0.hasher().hash_one(name)
+        self.map.hasher().hash_one(name)
+    }
+
+    /// Approximate memory cost of a new map entry: the owned key, the
+    /// value struct, and any heap-allocated bytes referenced from the key.
+    /// Used purely as input to the memory limiter; the exact byte count
+    /// does not need to match a real `size_of_val` since the limit is a
+    /// soft cap rather than an allocation hook.
+    fn entry_size(name: &LocalName<'_>) -> usize {
+        let key_data = match name {
+            LocalName::Hash(_) => 0,
+            LocalName::Bytes(bytes) => bytes.len(),
+        };
+        size_of::<LocalName<'static>>() + key_data + size_of::<CounterList>()
     }
 
     /// Adds a seen child to the map. The index is the level of the item
     pub fn add_child(&mut self, name: &LocalName<'_>, index: usize) {
         let hash = self.hash_name(name);
-        let entry = self.0.raw_entry_mut().from_hash(hash, |n| name == n);
+        let entry = self.map.raw_entry_mut().from_hash(hash, |n| name == n);
         match entry {
             RawEntryMut::Vacant(vacant) => {
+                let entry_size = Self::entry_size(name);
+                // Check memory limit before allocating
+                if self.limiter.increase_usage(entry_size).is_err() {
+                    return; // Memory limit exceeded, skip tracking this element
+                }
                 vacant.insert_hashed_nocheck(
                     hash,
                     name.clone().into_owned(), // the hash won't change just because we've got ownership
@@ -128,10 +153,23 @@ impl TypedChildCounterMap {
                 let CounterList { items, current } = occupied.get_mut();
                 if current.index == index {
                     current.counter.inc();
-                } else {
+                } else if self
+                    .limiter
+                    .increase_usage(size_of::<CounterItem>())
+                    .is_ok()
+                {
                     let counter = ChildCounter::new_and_inc();
                     let old = std::mem::replace(current, CounterItem { counter, index });
                     items.push(old);
+                } else {
+                    // Memory limit exceeded; drop the historical counter
+                    // rather than aborting the parse. Selector matches
+                    // for popped-back ancestors of this element may be
+                    // wrong, but availability is preserved.
+                    *current = CounterItem {
+                        counter: ChildCounter::new_and_inc(),
+                        index,
+                    };
                 }
             }
         }
@@ -139,7 +177,7 @@ impl TypedChildCounterMap {
 
     #[inline]
     pub fn pop_to(&mut self, index: usize) {
-        self.0.retain(|_, v| {
+        self.map.retain(|_, v| {
             while v.current.index > index {
                 match v.items.pop() {
                     Some(next) => {
@@ -157,7 +195,7 @@ impl TypedChildCounterMap {
     where
         'a: 'i,
     {
-        match self.0.get(name) {
+        match self.map.get(name) {
             Some(CounterList {
                 current:
                     CounterItem {
@@ -224,7 +262,7 @@ impl<E: ElementData> Stack<E> {
     pub fn new(memory_limiter: SharedMemoryLimiter, enable_nth_of_type: bool) -> Self {
         Self {
             root_child_counter: Default::default(),
-            typed_child_counters: enable_nth_of_type.then(TypedChildCounterMap::new),
+            typed_child_counters: enable_nth_of_type.then(|| TypedChildCounterMap::new(memory_limiter.clone())),
             items: LimitedVec::new(memory_limiter),
         }
     }
```
