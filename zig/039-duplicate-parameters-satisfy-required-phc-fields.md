# Duplicate Parameters Satisfy Required PHC Fields

## Classification

Security control failure, high severity.

## Affected Locations

- `lib/std/crypto/phc_encoding.zig:177`
- Function: `deserialize`

## Summary

The PHC deserializer counted the number of recognized fields encountered instead of tracking which specific fields were initialized. A duplicated recognized parameter could therefore increment the field count multiple times and satisfy the required-field check while another required field remained unset at its zero-initialized value.

## Provenance

Verified by Swival security analysis and runtime reproduction.

Scanner: [https://swival.dev](https://swival.dev)

Confidence: certain.

## Preconditions

- `HashResult` contains required non-optional fields.
- At least one recognized PHC parameter is repeatable in the input.
- The PHC string omits a required field but duplicates another recognized field.

## Proof

The vulnerable code initialized the output with zeroes:

```zig
var out = mem.zeroes(HashResult);
```

It then incremented a scalar counter for every recognized field or parameter:

```zig
set_fields += 1;
```

The final validation only compared the count against the number of required fields:

```zig
if (set_fields < expected_fields) return Error.InvalidEncoding;
```

Runtime reproduction confirmed:

```zig
phc.deserialize(HR, "$scrypt$m=1")
```

correctly rejects a missing required field, but:

```zig
const v = try phc.deserialize(HR, "$scrypt$m=1,m=1");
```

is accepted for:

```zig
const HR = struct {
    alg_id: []const u8,
    m: usize,
    t: usize,
};
```

The decoded value is:

```zig
v.alg_id == "scrypt"
v.m == 1
v.t == 0
```

Thus duplicated `m` satisfies the required-field count while required `t` remains unset.

The same behavior was reproduced with an argon2-like result shape containing required `m`, `t`, `p`, `salt`, and `hash`: an input with duplicated `m` and no `t` was accepted with `t == 0`.

## Why This Is A Real Bug

PHC strings encode password-hash parameters. Required KDF parameters must not silently default to zero when absent. Accepting malformed PHC input with missing required fields can cause password-hash verification or parameter handling to operate on invalid security parameters.

This is deterministic and attacker-triggerable by any caller-controlled PHC string containing duplicated recognized parameters.

## Fix Requirement

Track initialization per field, not by aggregate count.

The deserializer must:

- record each initialized `HashResult` field individually;
- reject duplicate recognized fields;
- require every non-optional field without a default value to have been initialized exactly once.

## Patch Rationale

The patch replaces the scalar `set_fields` counter with a boolean array indexed by `HashResult` field index:

```zig
const info = @typeInfo(HashResult).@"struct";
var set_fields: [info.field_names.len]bool = undefined;
@memset(&set_fields, false);
```

Each successfully decoded field marks its specific index:

```zig
set_fields[i] = true;
```

Before setting a field, the parser rejects duplicates:

```zig
if (set_fields[i]) return Error.InvalidEncoding;
```

The final required-field validation now checks every required field directly:

```zig
inline for (info.field_types, info.field_attrs, 0..) |p_type, p_attrs, i| {
    if (@typeInfo(p_type) != .optional and p_attrs.default_value_ptr == null and !set_fields[i]) {
        return Error.InvalidEncoding;
    }
}
```

This closes the fail-open condition because duplicate parameters no longer increase required-field satisfaction, and missing required fields are detected by identity.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/phc_encoding.zig b/lib/std/crypto/phc_encoding.zig
index 70f1f52bfb..268f81e213 100644
--- a/lib/std/crypto/phc_encoding.zig
+++ b/lib/std/crypto/phc_encoding.zig
@@ -81,19 +81,22 @@ pub fn deserialize(comptime HashResult: type, str: []const u8) Error!HashResult
 
     var out = mem.zeroes(HashResult);
     var it = mem.splitScalar(u8, str, fields_delimiter_scalar);
-    var set_fields: usize = 0;
+    const info = @typeInfo(HashResult).@"struct";
+    var set_fields: [info.field_names.len]bool = undefined;
+    @memset(&set_fields, false);
 
     while (true) {
         // Read the algorithm identifier
         if ((it.next() orelse return Error.InvalidEncoding).len != 0) return Error.InvalidEncoding;
         out.alg_id = it.next() orelse return Error.InvalidEncoding;
-        set_fields += 1;
+        set_fields[meta.fieldIndex(HashResult, "alg_id").?] = true;
 
         // Read the optional version number
         var field = it.next() orelse break;
         if (kvSplit(field)) |opt_version| {
             if (mem.eql(u8, opt_version.key, version_param_name)) {
                 if (@hasField(HashResult, "alg_version")) {
+                    if (set_fields[meta.fieldIndex(HashResult, "alg_version").?]) return Error.InvalidEncoding;
                     const ValueType = switch (@typeInfo(@TypeOf(out.alg_version))) {
                         .optional => |opt| opt.child,
                         else => @TypeOf(out.alg_version),
@@ -103,7 +106,7 @@ pub fn deserialize(comptime HashResult: type, str: []const u8) Error!HashResult
                         opt_version.value,
                         10,
                     ) catch return Error.InvalidEncoding;
-                    set_fields += 1;
+                    set_fields[meta.fieldIndex(HashResult, "alg_version").?] = true;
                 }
                 field = it.next() orelse break;
             }
@@ -115,9 +118,9 @@ pub fn deserialize(comptime HashResult: type, str: []const u8) Error!HashResult
         while (it_params.next()) |params| {
             const param = kvSplit(params) catch break;
             var found = false;
-            const info = @typeInfo(HashResult).@"struct";
-            inline for (info.field_names, info.field_types) |p_name, p_type| {
+            inline for (info.field_names, info.field_types, 0..) |p_name, p_type, i| {
                 if (mem.eql(u8, p_name, param.key)) {
+                    if (set_fields[i]) return Error.InvalidEncoding;
                     switch (@typeInfo(p_type)) {
                         .int => @field(out, p_name) = fmt.parseUnsigned(
                             p_type,
@@ -134,7 +137,7 @@ pub fn deserialize(comptime HashResult: type, str: []const u8) Error!HashResult
                             .{p_name},
                         ),
                     }
-                    set_fields += 1;
+                    set_fields[i] = true;
                     found = true;
                     break;
                 }
@@ -148,8 +151,9 @@ pub fn deserialize(comptime HashResult: type, str: []const u8) Error!HashResult
 
         // Read an optional salt
         if (@hasField(HashResult, "salt")) {
+            if (set_fields[meta.fieldIndex(HashResult, "salt").?]) return Error.InvalidEncoding;
             try out.salt.fromB64(field);
-            set_fields += 1;
+            set_fields[meta.fieldIndex(HashResult, "salt").?] = true;
         } else {
             return Error.InvalidEncoding;
         }
@@ -157,8 +161,9 @@ pub fn deserialize(comptime HashResult: type, str: []const u8) Error!HashResult
         // Read an optional hash
         field = it.next() orelse break;
         if (@hasField(HashResult, "hash")) {
+            if (set_fields[meta.fieldIndex(HashResult, "hash").?]) return Error.InvalidEncoding;
             try out.hash.fromB64(field);
-            set_fields += 1;
+            set_fields[meta.fieldIndex(HashResult, "hash").?] = true;
         } else {
             return Error.InvalidEncoding;
         }
@@ -167,14 +172,11 @@ pub fn deserialize(comptime HashResult: type, str: []const u8) Error!HashResult
 
     // Check that all the required fields have been set, excluding optional values and parameters
     // with default values
-    var expected_fields: usize = 0;
-    const info = @typeInfo(HashResult).@"struct";
-    inline for (info.field_types, info.field_attrs) |p_type, p_attrs| {
-        if (@typeInfo(p_type) != .optional and p_attrs.default_value_ptr == null) {
-            expected_fields += 1;
+    inline for (info.field_types, info.field_attrs, 0..) |p_type, p_attrs, i| {
+        if (@typeInfo(p_type) != .optional and p_attrs.default_value_ptr == null and !set_fields[i]) {
+            return Error.InvalidEncoding;
         }
     }
-    if (set_fields < expected_fields) return Error.InvalidEncoding;
 
     return out;
 }
```