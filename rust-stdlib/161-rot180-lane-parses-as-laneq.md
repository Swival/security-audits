# rot180_lane Parses As laneq

## Classification

Logic error, medium severity. Confidence: certain.

## Affected Locations

`library/stdarch/crates/stdarch-gen-arm/src/fn_suffix.rs:192`

## Summary

The NEON suffix parser maps the documented suffix token `rot180_lane` to `SuffixKind::Rot180LaneQ` instead of `SuffixKind::Rot180Lane`. As a result, generator input using `.rot180_lane` emits intrinsic suffixes containing `_rot180_laneq_...` rather than the intended `_rot180_lane_...`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Generator input contains a NEON suffix wildcard using the token `rot180_lane` for a vector type.

## Proof

`SuffixKind::from_str` receives suffix tokens as strings. The match arm for `"rot180_lane"` currently returns `Ok(SuffixKind::Rot180LaneQ)`. Later, NEON suffix expansion calls `make_neon_suffix`, where `SuffixKind::Rot180LaneQ` formats as:

```rust
format!("{prefix_q}_rot180_laneq_{prefix_char}{base_size}")
```

The intended non-`q` variant, `SuffixKind::Rot180Lane`, formats as:

```rust
format!("{prefix_q}_rot180_lane_{prefix_char}{base_size}")
```

The generator documentation confirms `.rot180_lane` is intended to produce `_rot180_lane_` at `library/stdarch/crates/stdarch-gen-arm/README.md:287`.

## Why This Is A Real Bug

This is a direct parser-to-formatter mismatch. The token name `rot180_lane` is mapped to the enum variant for `rot180_laneq`, while adjacent suffixes are mapped consistently:

- `rot270_lane` -> `SuffixKind::Rot270Lane`
- `rot270_laneq` -> `SuffixKind::Rot270LaneQ`
- `rot90_lane` -> `SuffixKind::Rot90Lane`
- `rot90_laneq` -> `SuffixKind::Rot90LaneQ`
- `rot180_laneq` -> `SuffixKind::Rot180LaneQ`

Therefore any parsed `rot180_lane` token reaches the `laneq` formatter path and emits the wrong intrinsic name. If both lane and laneq variants are generated, this can also create duplicate or incorrect Rust intrinsic definitions.

## Fix Requirement

Change the `"rot180_lane"` parser arm to return `Ok(SuffixKind::Rot180Lane)`.

## Patch Rationale

The patch aligns the parser with the documented suffix semantics and with the existing formatter implementation. It preserves the separate `"rot180_laneq"` mapping to `SuffixKind::Rot180LaneQ`, so only the incorrectly routed `rot180_lane` token changes behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/stdarch-gen-arm/src/fn_suffix.rs b/library/stdarch/crates/stdarch-gen-arm/src/fn_suffix.rs
index 26c156ae178..6fba3dc7447 100644
--- a/library/stdarch/crates/stdarch-gen-arm/src/fn_suffix.rs
+++ b/library/stdarch/crates/stdarch-gen-arm/src/fn_suffix.rs
@@ -188,7 +188,7 @@ fn from_str(s: &str) -> Result<Self, Self::Err> {
             "rot90_lane" => Ok(SuffixKind::Rot90Lane),
             "rot90_laneq" => Ok(SuffixKind::Rot90LaneQ),
             "rot180" => Ok(SuffixKind::Rot180),
-            "rot180_lane" => Ok(SuffixKind::Rot180LaneQ),
+            "rot180_lane" => Ok(SuffixKind::Rot180Lane),
             "rot180_laneq" => Ok(SuffixKind::Rot180LaneQ),
             "u" => Ok(SuffixKind::Unsigned),
             "nox" => Ok(SuffixKind::NoX),
```