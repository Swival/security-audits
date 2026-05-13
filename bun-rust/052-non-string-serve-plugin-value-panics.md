# Non-String Serve Plugin Value Panics

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`src/bunfig/bunfig.rs:1197`

## Summary

`serve.static.plugins` accepts either an array of strings or a single string. The non-array branch assumed the value was already known to be a string and called `e_string().expect(...)`. For booleans, objects, or other non-array/non-string values, that assumption was false, causing a panic during bunfig parsing.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Bun parses an attacker-controlled project bunfig file.
- The bunfig contains `serve.static.plugins`.
- `serve.static.plugins` is set to a non-array, non-string value such as `true`, `false`, or `{}`.

## Proof

`Bunfig::parse` parses the bunfig into an `Expr`, then `Parser::parse` reaches `serve.static` via `json.get_object(b"serve")` and `serve_obj2.get_object(b"static")`.

Inside `parse_serve_static`, arrays are handled explicitly. Every non-array value entered the `else` branch:

```rust
let s = config_plugins
    .data
    .e_string()
    .expect("infallible: variant checked");
```

No prior `ExprData::EString` check occurred in that branch. Therefore, `plugins = true`, `plugins = false`, `plugins = {}`, or another non-array/non-string value made `e_string()` return `None`, and `expect(...)` panicked.

The panic aborts the invoking Bun process during config parsing instead of returning `Invalid Bunfig`.

## Why This Is A Real Bug

The code documents its own invariant with `expect("infallible: variant checked")`, but the required variant check was missing. The reproducer confirms attacker-controlled bunfig content can reach this path and terminate the process. This is a denial-of-service bug because configuration parsing should reject invalid input through normal error handling, not panic.

## Fix Requirement

Explicitly validate that non-array `serve.static.plugins` values are strings. If the value is not a string, return the existing bunfig validation error path through `add_error`/`expect_string` instead of panicking.

## Patch Rationale

The patch adds `self.expect_string(&config_plugins)?;` before the existing `e_string().expect(...)` call in the non-array branch.

This preserves existing behavior for valid single-string plugin values while converting invalid non-array values into a normal `Invalid Bunfig` error. After `expect_string` returns `Ok(())`, the subsequent `e_string().expect(...)` invariant is true.

## Residual Risk

None

## Patch

```diff
diff --git a/src/bunfig/bunfig.rs b/src/bunfig/bunfig.rs
index f87f005f9f..399437d4ed 100644
--- a/src/bunfig/bunfig.rs
+++ b/src/bunfig/bunfig.rs
@@ -1588,6 +1588,7 @@ impl<'a> Parser<'a> {
                     }
                     break 'plugins Some(plugins);
                 } else {
+                    self.expect_string(&config_plugins)?;
                     let s = config_plugins
                         .data
                         .e_string()
```