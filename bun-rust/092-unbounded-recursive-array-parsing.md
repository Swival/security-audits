# Unbounded Recursive Array Parsing

## Classification

Denial of service, medium severity.

## Affected Locations

- `src/sql_jsc/postgres/DataCell.rs:163`
- `src/sql_jsc/postgres/DataCell.rs:171`
- `src/sql_jsc/postgres/DataCell.rs:173`
- `src/sql_jsc/postgres/DataCell.rs:869`
- `src/sql_jsc/postgres/DataCell.rs:876`
- `src/sql_jsc/postgres/DataCell.rs:1202`

## Summary

Text-format PostgreSQL array parsing recursively descends into nested `{...}` arrays and JSON `[...]` sub-arrays without enforcing a nesting limit. A malicious PostgreSQL server can return a deeply nested array column that causes repeated `parse_array` calls until the client thread stack is exhausted, aborting the database client process.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A client parses a text-format PostgreSQL array column.
- The array bytes are supplied by a PostgreSQL server or server-equivalent endpoint.
- The attacker can cause the server response to contain deeply nested array text.

## Proof

`from_bytes` dispatches text-format array OIDs to `parse_array`:

- `int4_array` text path calls `parse_array` at `src/sql_jsc/postgres/DataCell.rs:869`.
- `float4_array` text path calls `parse_array` at `src/sql_jsc/postgres/DataCell.rs:876`.
- The broad array-OID match calls `parse_array` at `src/sql_jsc/postgres/DataCell.rs:1202`.

Inside `parse_array`, each invocation allocates a stack buffer:

```rust
let mut stack_buffer = [0u8; 16 * 1024];
```

When the next element begins with the current array opening delimiter, the function recursively calls itself before any depth check exists:

```rust
let sub_array = parse_array(
    slice,
    bigint,
    array_type,
    global_object,
    Some(&mut sub_array_offset),
    is_json_sub_array,
)?;
```

The same recursive path exists for JSON sub-arrays beginning with `[`:

```rust
let sub_array = parse_array(
    slice,
    bigint,
    array_type,
    global_object,
    Some(&mut sub_array_offset),
    true,
)?;
```

There was no recursion depth counter or maximum nesting limit before either recursive call. Therefore, attacker-controlled nesting directly controls call-stack growth. Because every recursive frame contains a 16 KiB stack buffer, a deeply nested but otherwise small text array can exhaust the client stack and crash the process.

## Why This Is A Real Bug

The parser processes server-supplied bytes for text-format array columns. PostgreSQL array syntax supports nested arrays, and this implementation recursively parses them without a terminating resource bound. Stack exhaustion is a deterministic denial-of-service condition in the client process, not merely slow parsing or malformed input rejection.

The reproduced call chain confirms that non-binary array OIDs reach `parse_array`, and the recursive branches for both PostgreSQL arrays and JSON sub-arrays are reachable without a depth guard.

## Fix Requirement

Add and enforce a maximum array nesting depth before any recursive `parse_array` call. Top-level callers must initialize the depth, and recursive callers must increment it. Inputs exceeding the maximum depth must fail safely with an existing parse error.

## Patch Rationale

The patch introduces:

```rust
const MAX_ARRAY_NESTING_DEPTH: usize = 100;
```

`parse_array` now accepts a `depth: usize` parameter and rejects input once the depth exceeds the configured maximum:

```rust
if depth > MAX_ARRAY_NESTING_DEPTH {
    return Err(AnyPostgresError::UnsupportedArrayFormat);
}
```

All public/top-level text-array dispatch sites now call `parse_array(..., 0)`, while both recursive branches call `parse_array(..., depth + 1)`. This preserves existing parsing behavior for normal arrays while bounding stack growth for maliciously deep inputs.

## Residual Risk

None

## Patch

```diff
diff --git a/src/sql_jsc/postgres/DataCell.rs b/src/sql_jsc/postgres/DataCell.rs
index 5a173c70c7..060732b9a1 100644
--- a/src/sql_jsc/postgres/DataCell.rs
+++ b/src/sql_jsc/postgres/DataCell.rs
@@ -104,6 +104,8 @@ fn try_slice(slice: &[u8], count: usize) -> &[u8] {
     &slice[count..]
 }
 
+const MAX_ARRAY_NESTING_DEPTH: usize = 100;
+
 // PERF(port): `array_type` and `is_json_sub_array` were `comptime` in Zig (per-variant
 // monomorphization). Demoted to runtime here because they are only used in value
 // position (branch selectors), never type position. Profile in Phase B.
@@ -114,7 +116,12 @@ fn parse_array(
     global_object: &JSGlobalObject,
     offset: Option<&mut usize>,
     is_json_sub_array: bool,
+    depth: usize,
 ) -> Result<SQLDataCell> {
+    if depth > MAX_ARRAY_NESTING_DEPTH {
+        return Err(AnyPostgresError::UnsupportedArrayFormat);
+    }
+
     let closing_brace: u8 = if is_json_sub_array { b']' } else { b'}' };
     let opening_brace: u8 = if is_json_sub_array { b'[' } else { b'{' };
     if bytes.len() < 2 || bytes[0] != opening_brace {
@@ -177,6 +184,7 @@ fn parse_array(
                 global_object,
                 Some(&mut sub_array_offset),
                 is_json_sub_array,
+                depth + 1,
             )?;
             // errdefer sub_array.deinit() — Vec::push cannot fail in Rust (aborts on OOM)
             array.push(sub_array);
@@ -697,6 +705,7 @@ fn parse_array(
                                         global_object,
                                         Some(&mut sub_array_offset),
                                         true,
+                                        depth + 1,
                                     )?;
                                     array.push(sub_array);
                                     slice = try_slice(slice, sub_array_offset);
@@ -866,14 +875,14 @@ pub fn from_bytes(
             if binary {
                 from_bytes_typed_array::<i32>(T::int4_array, bytes)
             } else {
-                parse_array(bytes, bigint, T::int4_array, global_object, None, false)
+                parse_array(bytes, bigint, T::int4_array, global_object, None, false, 0)
             }
         }
         T::float4_array => {
             if binary {
                 from_bytes_typed_array::<f32>(T::float4_array, bytes)
             } else {
-                parse_array(bytes, bigint, T::float4_array, global_object, None, false)
+                parse_array(bytes, bigint, T::float4_array, global_object, None, false, 0)
             }
         }
         T::int2 => {
@@ -1199,7 +1208,7 @@ pub fn from_bytes(
         | T::timetz_array
         | T::timestamp_array
         | T::timestamptz_array
-        | T::interval_array) => parse_array(bytes, bigint, tag, global_object, None, false),
+        | T::interval_array) => parse_array(bytes, bigint, tag, global_object, None, false, 0),
         _ => Ok(SQLDataCell {
             tag: Tag::String,
             value: Value {
```