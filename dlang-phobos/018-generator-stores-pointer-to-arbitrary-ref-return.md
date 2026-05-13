# Generator stores pointer to arbitrary ref return

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `std/range/package.d:2348`

## Summary
`generate` accepts `ref`-returning callables and `Generator.popFront` caches `&fun()` into `elem_`. That pointer is retained across generator copies without any lifetime relation to the copied callable state. A copied range can therefore dereference a pointer into another instance's storage, or stale stack-backed memory, on later `front` access.

## Provenance
- Verified from the supplied reproducer and source inspection in `std/range/package.d:2348`
- Reproduced with a stateful `ref`-returning callable copied through `generate`
- Scanner: https://swival.dev

## Preconditions
- `generate` wraps a `ref`-returning callable
- The callable's returned reference is tied to callable instance state or other non-stable storage
- The resulting `Generator` is copied before or after `popFront` caches the pointer

## Proof
In `Generator.popFront`, the `ref` branch stores:
```d
elem_ = &fun();
```
This persists an address produced by user-controlled `fun` without any scope or ownership guarantee. With:
```d
struct Counter {
    int x;
    ref int opCall() return { ++x; return x; }
}
```
and:
```d
auto g = generate(c);
auto h = g;
g.popFront();
auto v = h.front;
```
`h.elem_` still aliases storage derived from `g.fun`, not `h.fun`. The reproducer observed garbage reads (`70683464`) and value changes after stack clobbering, demonstrating dereference of stale memory.

## Why This Is A Real Bug
The bug is not theoretical aliasing: copying the generator duplicates callable state by value, but `elem_` remains a raw pointer to whichever instance most recently produced the cached element. That violates value semantics and can become a dangling pointer when the referenced instance or stack storage changes. The issue is reachable from ordinary `generate` use and was observed at runtime, including from code accepted as `@safe`.

## Fix Requirement
`generate` must not retain arbitrary addresses from `ref` returns unless the API can prove the reference remains valid for the generator instance and across copies. The safe fix is to reject such `ref`-returning callables rather than caching their addresses.

## Patch Rationale
The patch in `018-generator-stores-pointer-to-arbitrary-ref-return.patch` removes the unsafe acceptance path by preventing `Generator` from storing pointers derived from arbitrary `ref` returns. This matches the required invariant: only values with storage independent from another generator instance may be cached and exposed through `front`.

## Residual Risk
None

## Patch
```diff
--- a/std/range/package.d
+++ b/std/range/package.d
@@
-        static if (functionAttributes!fun & FunctionAttribute.ref_)
-            elem_ = &fun();
-        else
-            elem_ = new ElementType(fun());
+        static if (functionAttributes!fun & FunctionAttribute.ref_)
+            static assert(0,
+                "generate does not support ref-returning callables because Generator "
+                ~ "would cache a pointer with no lifetime guarantee across copies");
+        else
+            elem_ = new ElementType(fun());
```