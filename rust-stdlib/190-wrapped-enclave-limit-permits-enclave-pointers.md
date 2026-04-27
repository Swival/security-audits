# Wrapped Enclave Limit Permits Enclave Pointers

## Classification

Validation gap, medium severity.

Confidence: certain.

## Affected Locations

`library/std/src/sys/pal/sgx/abi/mem.rs:92`

Reachable validation users:

`library/std/src/sys/pal/sgx/abi/usercalls/alloc.rs:434`

`library/std/src/sys/pal/sgx/abi/usercalls/alloc.rs:499`

## Summary

`is_user_range()` checks whether a pointer range is outside the SGX enclave. It correctly validates overflow for the caller-supplied `p + len - 1` range, but computes the enclave upper bound as:

```rust
base + (unsafe { ENCLAVE_SIZE } - 1)
```

without checked arithmetic.

If `base + ENCLAVE_SIZE - 1` wraps below `base`, enclave pointers above the wrapped value can satisfy the userspace predicate:

```rust
end < base || start > wrapped_limit
```

This permits enclave memory to be misclassified as userspace memory.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided source and patch evidence.

## Preconditions

`ENCLAVE_SIZE` causes `image_base() as usize + ENCLAVE_SIZE - 1` to overflow `usize`.

## Proof

A reproduced case used:

```text
base = usize::MAX - 0x0f
ENCLAVE_SIZE = 0x20
wrapped_limit = 0x0f
```

With overflow checks disabled, both of these enclave pointers were accepted by `is_user_range()`:

```text
is_user_range(base, 1) == true
is_user_range(base + 1, 1) == true
```

The range validation itself does not overflow in these examples: `start.checked_add(len - 1)` succeeds. The bug is isolated to the unchecked enclave-limit computation.

The predicate is security-relevant because SGX userspace copy paths trust `is_user_range()` before accessing caller-provided buffers:

```text
copy_to_userspace() validates dst with is_user_range()
copy_from_userspace() validates src with is_user_range()
```

## Why This Is A Real Bug

The function contract says `is_user_range()` returns `true` only when the specified range is in userspace and returns `false` on overflow.

The implementation enforces overflow safety for the input range but not for the enclave boundary. Under the stated precondition, unsigned wrapping changes the enclave end from a high address to a low address. The comparison then treats enclave addresses greater than the wrapped limit as userspace.

In optimized/std-style builds, this is a silent misclassification rather than a panic.

## Fix Requirement

Compute the enclave upper bound with `checked_add()` and return `false` if the bound cannot be represented.

## Patch Rationale

The patch replaces unchecked addition with checked addition:

```rust
let enclave_end = if let Some(end) = base.checked_add(unsafe { ENCLAVE_SIZE } - 1) {
    end
} else {
    return false;
};
```

This preserves the existing valid-case behavior while making overflow fail closed. If the enclave extent cannot be represented in `usize`, `is_user_range()` no longer accepts any pointer based on a wrapped enclave limit.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/sgx/abi/mem.rs b/library/std/src/sys/pal/sgx/abi/mem.rs
index e6ce15bed3c..6c55c8eca8d 100644
--- a/library/std/src/sys/pal/sgx/abi/mem.rs
+++ b/library/std/src/sys/pal/sgx/abi/mem.rs
@@ -89,5 +89,10 @@ pub fn is_user_range(p: *const u8, len: usize) -> bool {
     };
 
     let base = image_base() as usize;
-    end < base || start > base + (unsafe { ENCLAVE_SIZE } - 1) // unsafe ok: link-time constant
+    let enclave_end = if let Some(end) = base.checked_add(unsafe { ENCLAVE_SIZE } - 1) {
+        end
+    } else {
+        return false;
+    };
+    end < base || start > enclave_end // unsafe ok: link-time constant
 }
```