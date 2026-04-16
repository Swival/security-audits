# Ignored Unknown Fields Break Error Cleanup

## Classification

- Type: Denial of Service
- Severity: Medium
- Confidence: Certain

## Affected Locations

- `lib/std/zon/parse.zig:798`
- Specifically `Parser.parseStruct` cleanup bookkeeping for `ignore_unknown_fields` + `free_on_error`.

## Summary

`std.zon.parse.fromSliceAlloc` can leak allocations during failed struct parsing when both:

- `.ignore_unknown_fields = true`
- `.free_on_error = true`

If an ignored unknown field appears before a successfully parsed allocating field, and a later field fails to parse, the error cleanup frees the wrong prefix of runtime source field names. The initialized allocated field is skipped, leaking memory. Repeated attacker-controlled failed parses can exhaust memory in services using a long-lived allocator.

## Provenance

- Verified by reproduction.
- Source: Swival.dev Security Scanner — https://swival.dev

## Preconditions

- Parser is invoked with:
  - `ignore_unknown_fields = true`
  - `free_on_error = true`
- Target struct contains one or more allocating fields, such as `[]const u8`.
- Attacker controls ZON input.
- Unknown field precedes an initialized allocating field.
- A later field parse fails.

## Proof

Reproduced with input equivalent to:

```zig
const input =
    \\.{ .ignored = 0, .x = "AAAAAAAAAAAAAAAA", .y = "not_bool" }
;
```

Parsed as a struct with an allocating `x` field and a boolean `y` field:

```zig
const parsed = std.zon.parse.fromSliceAlloc(Victim, gpa, input, null, .{
    .ignore_unknown_fields = true,
    .free_on_error = true,
});
```

Observed leak output:

```text
error(SafeAllocator): leaked [addr: ..., len: 16 (0x10) align: 1] allocated at:
(empty stack trace)

leaks=1
```

Control flow:

1. `parseStruct` receives attacker-controlled struct literal fields.
2. Unknown `.ignored` is skipped because `ignore_unknown_fields` is enabled.
3. `initialized` is not incremented for `.ignored`.
4. `.x` is parsed and allocates memory.
5. `.y` fails to parse as `bool`.
6. `errdefer` cleanup iterates `fields.names[0..initialized]`.
7. Because the first runtime name is `.ignored`, cleanup looks up the unknown name and continues.
8. The initialized `.x` allocation is not freed.

## Why This Is A Real Bug

The parser explicitly offers `free_on_error` to clean up partially parsed values. In this case, that guarantee is violated for a valid option combination.

The bug is not cosmetic: the leaked allocation size is attacker-controlled through string or slice contents. A service repeatedly parsing untrusted ZON with a long-lived allocator can be driven into memory exhaustion by repeated failed parses.

## Fix Requirement

Cleanup must track the actual initialized destination struct field indices, not assume initialized fields correspond to a prefix of source field names.

## Patch Rationale

The patch adds an `initialized_fields` array of destination field indices. Each successfully parsed known field records its `field_index` before incrementing `initialized`.

On error, cleanup iterates `initialized_fields[0..initialized]` and frees exactly those initialized result fields. Ignored unknown fields are never recorded, so they cannot skew cleanup alignment.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/zon/parse.zig b/lib/std/zon/parse.zig
index 49ea45e034..67977863c5 100644
--- a/lib/std/zon/parse.zig
+++ b/lib/std/zon/parse.zig
@@ -827,9 +827,10 @@ const Parser = struct {
 
         // If we fail partway through, free all already initialized fields
         var initialized: usize = 0;
+        var initialized_fields: [info.field_names.len]usize = undefined;
         errdefer if (self.options.free_on_error and info.field_names.len > 0) {
-            for (fields.names[0..initialized]) |name_runtime| {
-                switch (field_indices.get(name_runtime.get(self.zoir)) orelse continue) {
+            for (initialized_fields[0..initialized]) |field_index| {
+                switch (field_index) {
                     inline 0...(info.field_names.len - 1) => |name_index| {
                         const name = info.field_names[name_index];
                         free(self.gpa, @field(result, name));
@@ -867,6 +868,7 @@ const Parser = struct {
                 else => unreachable, // Can't be out of bounds
             }
 
+            initialized_fields[initialized] = field_index;
             initialized += 1;
         }
 
```