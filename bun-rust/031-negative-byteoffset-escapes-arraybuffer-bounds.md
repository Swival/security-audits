# Negative byteOffset Escapes ArrayBuffer Bounds

## Classification

High severity out-of-bounds read / information disclosure.

Confidence: certain.

## Affected Locations

`src/runtime/ffi/FFIObject.rs:454`

## Summary

`bun:ffi` `FFI.ptr` accepts an `ArrayBufferView` and optional `byteOffset`. For negative offsets, `ptr_` subtracts from the view base with `saturating_sub`, but only rejects addresses greater than the view end. It does not reject addresses below the view base, so `FFI.ptr(view, -n)` can return a raw pointer before the view. `FFI.read.*` then accepts that numeric pointer and dereferences it, making process memory before the view readable by same-process JavaScript with `bun:ffi` access.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

Attacker-controlled JavaScript can call `bun:ffi` APIs in the same process, specifically `FFI.ptr` and `FFI.read`.

## Proof

The vulnerable flow is direct:

1. `ptr_` initializes `addr` to `array_buffer.ptr as usize`.
2. If `byteOffset` is negative, it computes:

```rust
addr = addr.saturating_sub(usize::try_from(bytei64 * -1).expect("int cast"));
```

3. The existing bounds check only rejects:

```rust
if addr > array_buffer.ptr as usize + array_buffer.byte_len as usize
```

4. Therefore, a small negative offset can produce `addr < array_buffer.ptr` while still being nonzero, below `MAX_ADDRESSABLE_MEMORY`, and not equal to the hard-coded invalid sentinel values.
5. `JSValue::from_ptr_address(addr)` returns this below-buffer address to JavaScript.
6. `reader::addr_from_args` accepts the returned number as a raw pointer.
7. `read_unaligned_at` dereferences it via:

```rust
(addr as *const T).read_unaligned()
```

This reproduces as an out-of-bounds read before the `ArrayBufferView`.

## Why This Is A Real Bug

The API converts a bounded JavaScript buffer view into an unconstrained raw pointer. Because the lower bound is not enforced after applying a negative `byteOffset`, attacker-controlled JavaScript can derive a pointer outside the original view. The subsequent `FFI.read.*` APIs intentionally dereference numeric raw addresses and do not retain any buffer provenance or bounds, so the invalid pointer is reachable and usable for memory disclosure.

## Fix Requirement

After applying `byteOffset`, reject any derived address outside the inclusive lower bound and upper bound of the backing `ArrayBufferView` range. Specifically, reject `addr < array_buffer.ptr as usize` in addition to the existing upper-bound rejection.

## Patch Rationale

The patch adds the missing lower-bound check immediately after offset application, at the same validation point as the existing upper-bound check. This preserves valid in-bounds offsets while rejecting negative offsets that move the pointer before the view.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/ffi/FFIObject.rs b/src/runtime/ffi/FFIObject.rs
index 74f45ea500..4623623975 100644
--- a/src/runtime/ffi/FFIObject.rs
+++ b/src/runtime/ffi/FFIObject.rs
@@ -640,7 +640,9 @@ fn ptr_(global_this: &JSGlobalObject, value: JSValue, byte_offset: Option<JSValu
             addr += usize::try_from(bytei64).expect("int cast");
         }
 
-        if addr > array_buffer.ptr as usize + array_buffer.byte_len as usize {
+        if addr < array_buffer.ptr as usize
+            || addr > array_buffer.ptr as usize + array_buffer.byte_len as usize
+        {
             return global_this.to_invalid_arguments(format_args!("byteOffset out of bounds"));
         }
     }
```