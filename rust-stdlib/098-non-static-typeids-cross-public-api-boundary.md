# Non-Static TypeIds Cross Public API Boundary

## Classification

Trust-boundary violation, medium severity, certain confidence.

## Affected Locations

`library/core/src/mem/type_info.rs:58`

## Summary

`Type::of<T: ?Sized>()` allowed callers to construct public `Type` metadata for non-`'static` types. That metadata exposed nested `TypeId` values through public fields such as `Field.ty`, `GenericType.ty`, and `Reference.pointee`, even though downstream crates commonly assume public `TypeId` values originate from `TypeId::of<T: 'static>`.

The patch changes `Type::of` to require `T: ?Sized + 'static`, aligning the public constructor with the existing `TypeId::of` lifetime boundary.

## Provenance

Verified from the supplied source, reproducer summary, and patch.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A crate consumes `TypeId` values obtained from `Type::of` metadata and assumes those IDs are derived only from `'static` types.

## Proof

The vulnerable API was:

```rust
pub const fn of<T: ?Sized>() -> Self {
    const { type_id::<T>().info() }
}
```

A non-`'static` lifetime could be embedded into reflected metadata and then extracted as a public `TypeId`:

```rust
#![feature(type_info)]

use std::any::TypeId;
use std::mem::type_info::{Generic, GenericType, Type, TypeKind};

struct Wrap<T>(T);

fn leak_id<'a>(_: &'a u8) -> TypeId {
    match const { Type::of::<Wrap<&'a u8>>() }.kind {
        TypeKind::Struct(s) => match s.generics[0] {
            Generic::Type(GenericType { ty, .. }) => ty,
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
}
```

A direct `TypeId::of::<&'a u8>()` in the same lifetime context fails because `'a` must outlive `'static`, but the `Type::of::<Wrap<&'a u8>>()` path compiled and returned a public `TypeId`.

## Why This Is A Real Bug

The API crossed a trust boundary by exporting `TypeId` values that did not satisfy the normal public `TypeId::of<T: 'static>` construction invariant.

The source documentation itself acknowledged the issue: `Type` and its fields could contain `TypeId`s not necessarily derived from types that outlive `'static`, and using those transitive IDs could break invariants assumed by other `TypeId` consumers.

Because those IDs were exposed through public metadata fields, downstream code could not distinguish static-derived IDs from non-static-derived IDs.

## Fix Requirement

`Type::of` must not expose ordinary public `TypeId` values derived from non-`'static` types.

Acceptable fixes are:

- Require `T: 'static` on `Type::of`.
- Or introduce a distinct non-static type identifier that cannot be confused with `TypeId`.

## Patch Rationale

The patch applies the minimal boundary-preserving fix:

```diff
-pub const fn of<T: ?Sized>() -> Self {
+pub const fn of<T: ?Sized + 'static>() -> Self {
```

This prevents the reproducer from constructing `Type` metadata for `Wrap<&'a u8>` unless `'a: 'static`.

Removing the warning comment is appropriate because the public constructor now enforces the same lifetime constraint expected by ordinary `TypeId` consumers.

## Residual Risk

None

## Patch

```diff
diff --git a/library/core/src/mem/type_info.rs b/library/core/src/mem/type_info.rs
index e4d47dedb86..1bfdac5437b 100644
--- a/library/core/src/mem/type_info.rs
+++ b/library/core/src/mem/type_info.rs
@@ -46,15 +46,9 @@ pub const fn info(self) -> Type {
 impl Type {
     /// Returns the type information of the generic type parameter.
     ///
-    /// Note: Unlike `TypeId`s obtained via `TypeId::of`, the `Type`
-    /// struct and its fields contain `TypeId`s that are not necessarily
-    /// derived from types that outlive `'static`. This means that using
-    /// the `TypeId`s (transitively) obtained from this function will
-    /// be able to break invariants that other `TypeId` consuming crates
-    /// may have assumed to hold.
     #[unstable(feature = "type_info", issue = "146922")]
     #[rustc_const_unstable(feature = "type_info", issue = "146922")]
-    pub const fn of<T: ?Sized>() -> Self {
+    pub const fn of<T: ?Sized + 'static>() -> Self {
         const { type_id::<T>().info() }
     }
 }
```