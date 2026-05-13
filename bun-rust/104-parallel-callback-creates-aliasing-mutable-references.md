# Parallel Callback Creates Aliasing Mutable References

## Classification

Memory corruption, high severity.

## Affected Locations

`src/bundler/linker_context/computeCrossChunkDependencies.rs:91`

## Summary

`compute_cross_chunk_dependencies` built one `CrossChunkDependencies` value containing mutable slice fields, then shared it across `ThreadPool::each_ptr` callbacks. Each callback cast the shared reference back to `*mut CrossChunkDependencies` and called `walk(&mut self)`, allowing concurrent tasks to materialize simultaneous mutable references to the same object. This violates Rust aliasing rules and creates undefined behavior in the bundler process.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Code splitting is enabled.
- The worker pool processes multiple chunks concurrently.
- The bundled source graph produces multiple chunks walked in parallel.

## Proof

The vulnerable implementation created one shared `CrossChunkDependencies` instance:

```rust
let mut cross_chunk_dependencies = CrossChunkDependencies {
    chunk_meta: &mut chunk_metas,
    import_records: ast.import_records,
    ...
};
```

It then passed `&mut cross_chunk_dependencies` into `each_ptr`:

```rust
(*(*parse_graph).pool.get().worker_pool).each_ptr(
    &mut cross_chunk_dependencies,
    |deps: &&mut CrossChunkDependencies<'_>, chunk: *mut Chunk, idx: usize| {
        let deps = &raw const **deps as *mut CrossChunkDependencies<'_>;
        unsafe { (*deps).walk(&mut *chunk, idx) };
    },
    chunks,
);
```

The callback recovered a mutable raw pointer to the same `CrossChunkDependencies` object and invoked:

```rust
pub fn walk(&mut self, chunk: &mut Chunk, chunk_index: usize)
```

With concurrent callbacks, this creates overlapping `&mut CrossChunkDependencies` references to the same object. `walk` then derives mutable references into shared mutable slice fields, including:

```rust
let chunk_meta = &mut deps.chunk_meta[chunk_index];
let import_records = deps.import_records[source_index as usize].slice_mut();
```

The original code also contained a TODO acknowledging the issue:

```rust
// TODO(port): `each_ptr` runs `walk` concurrently across worker threads with a shared
// `&mut CrossChunkDependencies`...
// needs UnsafeCell / raw pointers or a different parallel API.
```

## Why This Is A Real Bug

Rust requires `&mut` references to be exclusive for the duration of the borrow. The callback creates multiple live mutable references to the same `CrossChunkDependencies` object before any per-index partitioning can justify disjoint writes.

Even if chunk-specific writes are intended to target disjoint indices, the undefined behavior occurs when overlapping `&mut self` references are materialized. The unsafe cast bypasses borrow checking and invalidates Rust’s aliasing invariants, making this a memory-safety issue reachable from attacker-controlled bundled source graphs under the stated preconditions.

## Fix Requirement

Do not share a single `CrossChunkDependencies` value through parallel callbacks while calling a `&mut self` method on it. The implementation must either:

- Partition mutable state so each task owns an exclusive portion, or
- Use a representation based on raw pointers or `UnsafeCell` that does not create aliasing `&mut` references, with carefully documented synchronization and disjointness guarantees.

## Patch Rationale

The patch removes the parallel `each_ptr` callback and replaces it with sequential iteration:

```rust
for (idx, chunk) in chunks.iter_mut().enumerate() {
    cross_chunk_dependencies.walk(chunk, idx);
}
```

This ensures only one `&mut CrossChunkDependencies` borrow exists at a time. It also removes the unsafe `Sync` implementation for `CrossChunkDependencies`, because the structure is no longer shared across worker threads. Comments that described the previous concurrent shared-mutable model are updated to reflect the sequential walk.

This directly eliminates the aliasing condition while preserving the existing `walk(&mut self, ...)` API.

## Residual Risk

None.

## Patch

`104-parallel-callback-creates-aliasing-mutable-references.patch`

```diff
diff --git a/src/bundler/linker_context/computeCrossChunkDependencies.rs b/src/bundler/linker_context/computeCrossChunkDependencies.rs
index 66416ce421..f3427823b0 100644
--- a/src/bundler/linker_context/computeCrossChunkDependencies.rs
+++ b/src/bundler/linker_context/computeCrossChunkDependencies.rs
@@ -38,7 +38,7 @@ pub fn compute_cross_chunk_dependencies(
         // scope end; in Rust we construct on the stack and let it drop.
         //
         // `ctx` / `symbols` / `chunks` are stored as raw pointers so the struct does not
-        // hold a borrow on `c` or `chunks` across the `each_ptr` call.
+        // hold a borrow on `c` or `chunks` while walking each chunk.
@@ -58,8 +58,6 @@ pub fn compute_cross_chunk_dependencies(
         // intermediate `&` borrow is pushed before the `split_mut()` calls
         // below — matches the `ctx_ref` construction pattern just above.
         let symbols_ref = bun_ptr::BackRef::from(core::ptr::NonNull::from(&mut c.graph.symbols));
-        let parse_graph = c.parse_graph;
-
         let ast = c.graph.ast.split_mut();
         let meta = c.graph.meta.split_mut();
         let files = c.graph.files.split_mut();
@@ -80,24 +78,9 @@ pub fn compute_cross_chunk_dependencies(
             symbols: symbols_ref,
         };
 
-        // SAFETY: `parse_graph` backref valid for the link pass.
-        unsafe {
-            (*(*parse_graph).pool.get().worker_pool).each_ptr(
-                &mut cross_chunk_dependencies,
-                |deps: &&mut CrossChunkDependencies<'_>, chunk: *mut Chunk, idx: usize| {
-                    // SAFETY: each_ptr partitions `chunks` by index; `walk` only mutates
-                    // chunk_meta[idx] / per-source columns disjointly (Zig shared-mutable
-                    // pattern). See TODO(port) below re: UnsafeCell.
-                    let deps = &raw const **deps as *mut CrossChunkDependencies<'_>;
-                    unsafe { (*deps).walk(&mut *chunk, idx) };
-                },
-                chunks,
-            );
+        for (idx, chunk) in chunks.iter_mut().enumerate() {
+            cross_chunk_dependencies.walk(chunk, idx);
         }
-        // TODO(port): `each_ptr` runs `walk` concurrently across worker threads with a shared
-        // `&mut CrossChunkDependencies`. In Zig this is permitted; in Rust the shared-mutable
-        // access (symbols.assignChunkIndex, chunk_meta[i] writes, import_records[i] writes)
-        // needs UnsafeCell / raw pointers or a different parallel API.
     }
@@ -125,44 +107,25 @@ pub struct CrossChunkDependencies<'a> {
     // erased (`'static`) so the outer `CrossChunkDependencies<'_>` borrow is not tied
     // to the LinkerContext's own invariant lifetime parameter.
     ctx: bun_ptr::BackRef<LinkerContext<'static>>,
-    // `BackRef` — `walk` runs concurrently across worker threads; each touches
-    // disjoint per-chunk symbol slots via `Map::assign_chunk_index(&self)`,
-    // which is a Relaxed store to `Symbol.chunk_index: AtomicU32`. Holding
-    // `&mut Map` here would assert whole-map exclusivity per thread = aliasing
-    // UB; `BackRef::Deref` yields the shared `&Map` each task needs.
+    // `BackRef` — `walk` touches symbol slots via `Map::assign_chunk_index(&self)`,
+    // which is a Relaxed store to `Symbol.chunk_index: AtomicU32`. Holding `&mut Map`
+    // here would assert whole-map exclusivity while other graph columns are borrowed.
     symbols: bun_ptr::BackRef<bun_ast::symbol::Map>,
 }
 
-// SAFETY: `CrossChunkDependencies` is shared across worker threads via
-// `ThreadPool::each_ptr`, mirroring Zig's `*@This()` pattern. Mutation is
-// partitioned per-chunk-index (chunk_meta[i], symbols.assign_chunk_index);
-// see TODO(port) above re: UnsafeCell for a stricter model in Phase B.
-unsafe impl Sync for CrossChunkDependencies<'_> {}
-
 impl<'a> CrossChunkDependencies<'a> {
-    // CONCURRENCY: `each_ptr` callback — runs on worker threads, one task per
-    // `chunk_index`. Writes: `self.chunk_meta[chunk_index]` (per-chunk
-    // disjoint), `self.import_records[source_index][rec].{path,source_index}`
-    // (per-chunk disjoint via `chunk.files_with_parts_in_chunk`),
+    // Writes: `self.chunk_meta[chunk_index]`,
+    // `self.import_records[source_index][rec].{path,source_index}`, and
     // `symbols.assign_chunk_index(ref)` (Relaxed atomic store to
-    // `Symbol.chunk_index: AtomicU32`; per-symbol-ref disjoint by chunk
-    // membership — debug-asserted in `assign_chunk_index`).
-    // Reads `ctx`/`chunks`/SoA columns shared. Never forms `&mut
-    // LinkerContext` (`ctx` is `*const`, deref'd to `&`); `&mut self` is
-    // recovered from a raw pointer per task, so no two tasks hold a live
-    // `&mut CrossChunkDependencies` over the same field at once — but the
-    // `&mut [ChunkMeta]` / `&mut [Vec<ImportRecord>]` whole-slice borrows are
-    // partitioned by index only (Zig invariant), not by Rust type.
+    // `Symbol.chunk_index: AtomicU32`).
     pub fn walk(&mut self, chunk: &mut Chunk, chunk_index: usize) {
         let deps = self;
         // `ctx` / `chunks` are `BackRef`s into `LinkerContext` / the caller's chunk
-        // slice, valid for the link pass; `walk` runs under `each_ptr` with per-chunk
-        // partitioning (see PORT NOTE on the struct fields). `chunks` aliases the
-        // `each_ptr` slice but is only read here.
+        // slice, valid for the link pass. `chunks` is only read here.
```