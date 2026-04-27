# Shared Slice Reference Over Mutable Userspace

## Classification

High severity invariant violation.

## Affected Locations

`library/std/src/sys/pal/sgx/abi/usercalls/alloc.rs:692`

## Summary

`UserRef<[T]>::iter` created a Rust `&[T]` over userspace memory by casting `self.as_raw_ptr()` and calling slice iteration. `UserRef` explicitly documents that userspace may write the backing memory at any time, so modeling that memory as an immutable Rust slice violates Rust aliasing rules. The patch replaces `slice::Iter<'a, T>` with a raw-pointer iterator that returns `&UserRef<T>` without constructing `&[T]` or `&T`.

## Provenance

Verified from the provided source, reproduced from the described code path, and reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Caller has a `UserRef<[T]>` backed by user memory.
- Code calls the public `UserRef<[T]>::iter` method.
- Userspace may mutate the backing buffer while the iterator or yielded item lifetime is live, which is allowed by the `UserRef` contract.

## Proof

The affected implementation was:

```rust
pub fn iter(&self) -> Iter<'_, T>
where
    T: UserSafe,
{
    unsafe { Iter((&*self.as_raw_ptr()).iter()) }
}
```

This converts the raw user-memory slice pointer into `&[T]` and calls `slice::iter`.

The iterator wrapper stored:

```rust
pub struct Iter<'a, T: 'a + UserSafe>(slice::Iter<'a, T>);
```

Its `next` implementation then obtained `&T` from `slice::Iter` before converting it to `&UserRef<T>`:

```rust
unsafe { self.0.next().map(|e| UserRef::from_ptr(e)) }
```

In core, `slice::Iter` is created from `&'a [T]`, and `Iterator::next` returns element references derived from that slice. Therefore the public `UserRef<[T]>::iter` path creates immutable Rust references to memory that userspace is contractually allowed to mutate concurrently.

## Why This Is A Real Bug

`UserRef` states that userspace may always write to backing memory at any time, and that even `&mut UserRef<T>` is not exclusive. This design avoids relying on ordinary Rust aliasing guarantees for untrusted memory.

Creating `&[T]` and then `&T` reintroduces ordinary Rust shared-reference invariants. Rust shared references require the referenced memory not be concurrently mutated except through `UnsafeCell`. The backing userspace memory is not protected by that invariant, so the safe public `iter` method internally creates references whose assumptions can be false.

A practical trigger is an enclave holding `&UserRef<[u8]>` or `User<[u8]>`, calling `.iter()`, and the untrusted host mutating the user buffer while the iterator or yielded reference is live. That mutation is allowed by the `UserRef` contract but invalidates the `&[T]`/`&T` model introduced by `iter`.

## Fix Requirement

Implement immutable user-slice iteration using raw pointer arithmetic and length tracking. The iterator must return `&UserRef<T>` without constructing `&[T]`, `slice::Iter<'a, T>`, or intermediate `&T` references to userspace memory.

## Patch Rationale

The patch imports `PhantomData` and changes `Iter` from a wrapper around `slice::Iter<'a, T>` to an explicit raw-pointer iterator:

```rust
pub struct Iter<'a, T: 'a + UserSafe> {
    ptr: *const T,
    len: usize,
    _marker: PhantomData<&'a UserRef<T>>,
}
```

`UserRef<[T]>::iter` now initializes the iterator from the user-slice base pointer and length:

```rust
Iter { ptr: self.as_ptr(), len: self.len(), _marker: PhantomData }
```

`Iterator::next` now checks the remaining length, advances the raw pointer with pointer arithmetic, decrements the length, and casts the current element address directly to `*const UserRef<T>`:

```rust
if self.len == 0 {
    return None;
}
let ptr = self.ptr;
self.ptr = self.ptr.wrapping_add(1);
self.len -= 1;
unsafe { Some(&*(ptr as *const UserRef<T>)) }
```

This preserves the lifetime relationship to the borrowed `UserRef<[T]>` through `PhantomData` while avoiding construction of immutable Rust references to the underlying userspace `T` values.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/sgx/abi/usercalls/alloc.rs b/library/std/src/sys/pal/sgx/abi/usercalls/alloc.rs
index c2694316249..70d62a1cc4f 100644
--- a/library/std/src/sys/pal/sgx/abi/usercalls/alloc.rs
+++ b/library/std/src/sys/pal/sgx/abi/usercalls/alloc.rs
@@ -6,6 +6,7 @@
 use crate::arch::asm;
 use crate::cell::UnsafeCell;
 use crate::convert::TryInto;
+use crate::marker::PhantomData;
 use crate::mem::{self, ManuallyDrop, MaybeUninit};
 use crate::ops::{CoerceUnsized, Deref, DerefMut, Index, IndexMut};
 use crate::ptr::{self, NonNull};
@@ -690,7 +691,7 @@ pub fn iter(&self) -> Iter<'_, T>
     where
         T: UserSafe, // FIXME: should be implied by [T]: UserSafe?
     {
-        unsafe { Iter((&*self.as_raw_ptr()).iter()) }
+        Iter { ptr: self.as_ptr(), len: self.len(), _marker: PhantomData }
     }
 
     /// Returns an iterator that allows modifying each value.
@@ -706,7 +707,11 @@ pub fn iter_mut(&mut self) -> IterMut<'_, T>
 ///
 /// This struct is created by the `iter` method on `UserRef<[T]>`.
 #[unstable(feature = "sgx_platform", issue = "56975")]
-pub struct Iter<'a, T: 'a + UserSafe>(slice::Iter<'a, T>);
+pub struct Iter<'a, T: 'a + UserSafe> {
+    ptr: *const T,
+    len: usize,
+    _marker: PhantomData<&'a UserRef<T>>,
+}
 
 #[unstable(feature = "sgx_platform", issue = "56975")]
 impl<'a, T: UserSafe> Iterator for Iter<'a, T> {
@@ -714,7 +719,13 @@ impl<'a, T: UserSafe> Iterator for Iter<'a, T> {
 
     #[inline]
     fn next(&mut self) -> Option<Self::Item> {
-        unsafe { self.0.next().map(|e| UserRef::from_ptr(e)) }
+        if self.len == 0 {
+            return None;
+        }
+        let ptr = self.ptr;
+        self.ptr = self.ptr.wrapping_add(1);
+        self.len -= 1;
+        unsafe { Some(&*(ptr as *const UserRef<T>)) }
     }
 }
```