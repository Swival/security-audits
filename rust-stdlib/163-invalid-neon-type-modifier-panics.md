# Invalid `neon_type` Modifier Panics

## Classification

error-handling bug, medium severity, confidence certain

## Affected Locations

`library/stdarch/crates/stdarch-gen-arm/src/wildcards.rs:93`

## Summary

Parsing a `neon_type` wildcard with an unsupported dot modifier panics instead of returning `Err(String)` through the `FromStr` API. The panic is caused by unwrapping the result of `SuffixKind::from_str` for user-controlled wildcard modifier text.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

A caller parses a `neon_type` wildcard with an unsupported dot modifier, such as `neon_type.bad`.

## Proof

The wildcard parser regex in `library/stdarch/crates/stdarch-gen-arm/src/wildcards.rs` captures:

- `wildcard = neon_type`
- `modifiers = bad`

The `neon_type` match arm then calls:

```rust
let suffix_kind = SuffixKind::from_str(str_suffix);
return Ok(Wildcard::NEONType(index, tuple, Some(suffix_kind.unwrap())));
```

For unsupported suffixes, `SuffixKind::from_str` returns `Err(...)`. The immediate `unwrap()` panics with `called Result::unwrap() on an Err value`.

This path is reachable through `WildString::from_str`, which parses wildcard contents using `s[start..idx].parse()?` in `library/stdarch/crates/stdarch-gen-arm/src/wildstring.rs:203`. YAML spec fields such as `Signature.name` are parsed as `WildString`, so malformed spec input like `vfoo{neon_type.bad}` reaches the panic path during parsing.

## Why This Is A Real Bug

`Wildcard::from_str` exposes a fallible `Result<Self, String>` interface and already returns structured parse errors for invalid indices, tuple sizes, type modifiers, and invalid wildcard forms. The `neon_type` modifier path bypasses that error-handling contract by panicking on invalid input.

Malformed spec input can therefore abort the generator instead of producing a recoverable parse error.

## Fix Requirement

Replace the `unwrap()` on `SuffixKind::from_str(str_suffix)` with fallible propagation that converts invalid suffixes into `Err(String)`.

## Patch Rationale

The patch changes the `neon_type` modifier handling to map an invalid suffix into the parser’s existing `String` error type:

```rust
let suffix_kind = SuffixKind::from_str(str_suffix)
    .map_err(|_| format!("{str_suffix:#?} is not a valid suffix"))?;
return Ok(Wildcard::NEONType(index, tuple, Some(suffix_kind)));
```

This preserves valid parsing behavior while ensuring invalid modifiers follow the same `Result`-based error path as other malformed wildcard components.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/stdarch-gen-arm/src/wildcards.rs b/library/stdarch/crates/stdarch-gen-arm/src/wildcards.rs
index 6c40d88df45..fc88f6b09b1 100644
--- a/library/stdarch/crates/stdarch-gen-arm/src/wildcards.rs
+++ b/library/stdarch/crates/stdarch-gen-arm/src/wildcards.rs
@@ -89,8 +89,9 @@ fn from_str(s: &str) -> Result<Self, Self::Err> {
                 ("type", index, None, None) => Ok(Wildcard::Type(index)),
                 ("neon_type", index, tuple, modifier) => {
                     if let Some(str_suffix) = modifier {
-                        let suffix_kind = SuffixKind::from_str(str_suffix);
-                        return Ok(Wildcard::NEONType(index, tuple, Some(suffix_kind.unwrap())));
+                        let suffix_kind = SuffixKind::from_str(str_suffix)
+                            .map_err(|_| format!("{str_suffix:#?} is not a valid suffix"))?;
+                        return Ok(Wildcard::NEONType(index, tuple, Some(suffix_kind)));
                     } else {
                         Ok(Wildcard::NEONType(index, tuple, None))
                     }
```