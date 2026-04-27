// Bug: Type::of<T: ?Sized>() lets callers construct Type metadata for non-'static T,
// then pluck a public TypeId out of nested fields, defeating the TypeId 'static contract.
// Expected: TypeId values exposed to public API must come from T: 'static.
// Observed: const { Type::of::<Wrap<&'a u8>>() } compiles for non-'static 'a.
// Build/run: rustup run nightly rustc 098-non-static-typeids-cross-public-api-boundary.rs -o /tmp/poc098 && /tmp/poc098

#![feature(type_info)]

use std::any::TypeId;
use std::mem::type_info::{Generic, GenericType, Type, TypeKind};

struct Wrap<T: ?Sized>(T);

fn leak_id<'a>(_: &'a u8) -> TypeId {
    match const { Type::of::<Wrap<&'a u8>>() }.kind {
        TypeKind::Struct(s) => match s.generics[0] {
            Generic::Type(GenericType { ty, .. }) => ty,
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
}

fn main() {
    let local = 7u8;
    let id = leak_id(&local);
    let static_id = TypeId::of::<&'static u8>();
    println!("non-static id == &'static u8 id: {}", id == static_id);
    println!("BUG TRIGGERED: extracted public TypeId from non-'static type via Type::of");
}
