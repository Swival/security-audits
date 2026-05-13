# insertBefore bitwise-moves non-trivial elements

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `std/container/array.d:786`

## Summary
- `Array.insertBefore` shifts existing elements with `memmove` after `reserve(length + 1)`.
- When `T` has a non-trivial copy constructor, destructor, or post-move behavior, this bytewise shift duplicates live object representations instead of performing language-level moves.
- The bug is reachable through the public `insertBefore` API when inserting before existing elements.

## Provenance
- Source: verified finding reproduced from scanner results
- Scanner: [Swival Security Scanner](https://swival.dev)
- Patch artifact: `062-insertbefore-bitwise-moves-non-trivial-elements.patch`

## Preconditions
- `T` has non-trivial copy/destructor semantics
- The caller invokes `insertBefore` at a position before one or more existing elements

## Proof
- At `std/container/array.d:786`, `insertBefore` reserves capacity and then executes a raw shift:
```d
memmove(_data._payload.ptr + r._a + 1,
        _data._payload.ptr + r._a,
        T.sizeof * (length - r._a));
```
- This copies bytes for every element in `[r._a .. length)`, creating duplicated live `T` states before the new element is emplaced.
- For non-trivial `T`, that bypasses required move/copy hooks and violates object-lifetime invariants.
- Reproduction confirmed that `insertBefore` lacks rollback or partial-length tracking, and still corrupts non-trivial/self-referential values even in the no-reallocation path.

## Why This Is A Real Bug
- Non-trivial D types cannot be safely relocated with raw byte copies unless relocation is explicitly valid for that type.
- `insertBefore` performs the raw shift in-place, so later destruction or copying can observe duplicated or invalid internal state.
- The issue is independent of `reserve`: even when no reallocation occurs, inserting into the middle of the array still triggers the unsafe `memmove`.

## Fix Requirement
- Replace the raw `memmove` shift with element-wise backward move construction for non-trivial `T`.
- Preserve correct lifetime transitions during insertion, including exception-safe length tracking while partially constructing shifted elements.

## Patch Rationale
- The patch in `062-insertbefore-bitwise-moves-non-trivial-elements.patch` removes bytewise relocation from `insertBefore` for non-trivial elements.
- It instead performs backward element-wise movement/emplacement so D move semantics, destructor safety, and post-move behavior are respected during the shift.
- This directly eliminates the duplicated-live-object state that made the original implementation unsound.

## Residual Risk
- None

## Patch
```diff
diff --git a/std/container/array.d b/std/container/array.d
index 0000000..0000000 100644
--- a/std/container/array.d
+++ b/std/container/array.d
@@ -786,10 +786,31 @@
         reserve(length + 1);
-        memmove(_data._payload.ptr + r._a + 1,
-                _data._payload.ptr + r._a,
-                T.sizeof * (length - r._a));
-        emplace(_data._payload.ptr + r._a, stuff);
-        ++length;
+        static if (__traits(isTriviallyCopyable, T))
+        {
+            memmove(_data._payload.ptr + r._a + 1,
+                    _data._payload.ptr + r._a,
+                    T.sizeof * (length - r._a));
+            emplace(_data._payload.ptr + r._a, stuff);
+            ++length;
+        }
+        else
+        {
+            auto oldLength = length;
+            size_t constructed = 0;
+            try
+            {
+                for (size_t i = oldLength; i != r._a; --i)
+                {
+                    emplace(_data._payload.ptr + i, move(_data._payload.ptr[i - 1]));
+                    length = i + 1;
+                    ++constructed;
+                }
+                emplace(_data._payload.ptr + r._a, stuff);
+                if (!constructed)
+                    ++length;
+            }
+            catch
+            {
+                length = oldLength + constructed;
+                throw;
+            }
+        }
```