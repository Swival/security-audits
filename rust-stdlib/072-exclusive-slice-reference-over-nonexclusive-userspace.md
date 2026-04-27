# Exclusive Slice Reference Over Nonexclusive Userspace

## Classification

Invariant violation, high severity.

## Affected Locations

`library/std/src/sys/pal/sgx/abi/usercalls/alloc.rs:700`

## Summary

`UserRef<[T]>::iter_mut` created a temporary `&mut [T]` over userspace memory and delegated to `slice::IterMut`. This violated the documented invariant of `UserRef`: `&mut UserRef<T>` is not exclusive because userspace may mutate the backing memory at any time. Forming `&mut [T]` and yielding through `slice::IterMut` requires exclusive access, so concurrent host writes can cause Rust undefined behavior inside enclave code.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Enclave code calls `UserRef<[T]>::iter_mut` on userspace memory.

## Proof

The affected implementation was:

```rust
unsafe { IterMut((&mut *self.as_raw_mut_ptr()).iter_mut()) }
```

This casts the userspace-backed raw slice pointer into `&mut [T]`, then constructs `slice::IterMut`. Both `&mut [T]` and `slice::IterMut` rely on exclusive access to the referenced elements for the lifetime of the borrow.

The type documentation explicitly states the opposite for this memory:

```rust
Unlike regular mutable references, these are not exclusive. Userspace may always
write to the backing memory at any time, so it can't be assumed that there
the pointed-to memory is uniquely borrowed.
```

A malicious or concurrent userspace can keep writing to a buffer while enclave code calls `UserRef::<[u8]>::iter_mut` or advances the iterator. The enclave has then formed exclusive Rust references over memory that remains externally mutable, violating Rust aliasing rules and enabling UB or optimizer miscompilation.

## Why This Is A Real Bug

The bug is reachable through the public `iter_mut` method. The abstraction intentionally models userspace memory as nonexclusive even through mutable `UserRef` references. Creating `&mut [T]` contradicts that model and imposes a stronger aliasing guarantee than the backing memory can satisfy. This is not only a documentation mismatch: Rust treats `&mut` exclusivity as an optimization invariant, so violating it is undefined behavior.

## Fix Requirement

Implement the mutable iterator using raw pointers and length tracking, and return `&mut UserRef<T>` elements directly from raw element pointers without ever constructing `&mut [T]` or `slice::IterMut<'_, T>` over userspace memory.

## Patch Rationale

The patch replaces the internal `slice::IterMut<'a, T>` with:

```rust
pub struct IterMut<'a, T: 'a + UserSafe> {
    ptr: *mut T,
    len: usize,
    _marker: crate::marker::PhantomData<&'a mut UserRef<T>>,
}
```

`UserRef<[T]>::iter_mut` now initializes the iterator from `self.as_mut_ptr()` and `self.len()`. `Iterator::next` checks the remaining length, returns the current element via `UserRef::from_mut_ptr(ptr)`, then advances the raw pointer.

This preserves the public API while avoiding construction of an exclusive Rust slice reference over nonexclusive userspace memory.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/sgx/abi/usercalls/alloc.rs b/library/std/src/sys/pal/sgx/abi/usercalls/alloc.rs
index c2694316249..8b5517f7270 100644
--- a/library/std/src/sys/pal/sgx/abi/usercalls/alloc.rs
+++ b/library/std/src/sys/pal/sgx/abi/usercalls/alloc.rs
@@ -698,7 +698,11 @@ pub fn iter_mut(&mut self) -> IterMut<'_, T>
     where
         T: UserSafe, // FIXME: should be implied by [T]: UserSafe?
     {
-        unsafe { IterMut((&mut *self.as_raw_mut_ptr()).iter_mut()) }
+        IterMut {
+            ptr: self.as_mut_ptr(),
+            len: self.len(),
+            _marker: crate::marker::PhantomData,
+        }
     }
 }
 
@@ -722,7 +726,11 @@ fn next(&mut self) -> Option<Self::Item> {
 ///
 /// This struct is created by the `iter_mut` method on `UserRef<[T]>`.
 #[unstable(feature = "sgx_platform", issue = "56975")]
-pub struct IterMut<'a, T: 'a + UserSafe>(slice::IterMut<'a, T>);
+pub struct IterMut<'a, T: 'a + UserSafe> {
+    ptr: *mut T,
+    len: usize,
+    _marker: crate::marker::PhantomData<&'a mut UserRef<T>>,
+}
 
 #[unstable(feature = "sgx_platform", issue = "56975")]
 impl<'a, T: UserSafe> Iterator for IterMut<'a, T> {
@@ -730,7 +738,13 @@ impl<'a, T: UserSafe> Iterator for IterMut<'a, T> {
 
     #[inline]
     fn next(&mut self) -> Option<Self::Item> {
-        unsafe { self.0.next().map(|e| UserRef::from_mut_ptr(e)) }
+        if self.len == 0 {
+            return None;
+        }
+        let ptr = self.ptr;
+        self.len -= 1;
+        self.ptr = unsafe { self.ptr.add(1) };
+        unsafe { Some(UserRef::from_mut_ptr(ptr)) }
     }
 }
```