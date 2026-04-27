# unchecked parameter index underflows

## Classification

validation gap, medium severity

## Affected Locations

`library/test/src/term/terminfo/parm.rs:278`

## Summary

`expand` accepts `%p0` as a parameter reference, subtracts one from the parsed digit, and indexes `mparams` with the result. Because terminfo parameters are 1-indexed, `0` is invalid and should return `Err`. Instead, `0` underflows during `d as usize - 1` and causes a panic, allowing malformed capability strings to deny service to callers that expand them.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A caller expands a capability string containing `%p0`.
- The capability string reaches `expand`.
- The caller expects malformed terminfo input to be handled as `Err` rather than as a panic.

## Proof

The reproduced execution path is:

- `%` is parsed by `expand` and enters `Percent`.
- `p` in `Percent` switches state to `PushParam`.
- `0` in `PushParam` reaches `cur.to_digit(10)` at `library/test/src/term/terminfo/parm.rs:277`.
- `Some(d) => d as usize - 1` at `library/test/src/term/terminfo/parm.rs:278` accepts `d == 0`.
- In debug builds, subtracting one from zero panics with `attempt to subtract with overflow`.
- In release-style wrapping behavior, the computed index becomes `usize::MAX`, and indexing `mparams[usize::MAX]` still panics.

A minimal reproducer is equivalent to calling `expand` with `%p0`, one numeric parameter, and a fresh `Variables` value. The runtime PoC confirmed that `%p0` panics at `parm.rs:278`.

Reachability is real because terminfo strings are parsed into `TermInfo.strings` and expanded through `reset` / `apply_cap` via `expand` at `library/test/src/term/terminfo/mod.rs:148` and `library/test/src/term/terminfo/mod.rs:184`.

## Why This Is A Real Bug

The code comment states that parameters are 1-indexed, but the implementation accepts any decimal digit before subtracting one. `%p0` is therefore treated as syntactically valid long enough to trigger arithmetic underflow or an out-of-bounds array access. This violates the function’s error-handling model for malformed format input and converts invalid caller-supplied capability data into a process panic.

## Fix Requirement

Reject parameter digits outside `1..=9` before subtracting and indexing `mparams`.

## Patch Rationale

The patch constrains the accepted digit range at the parse site:

```rust
Some(d @ 1..=9) => d as usize - 1,
_ => return Err("bad param number".to_string()),
```

This preserves valid `%p1` through `%p9` behavior while making `%p0` and non-digit parameter references fail with the existing `"bad param number"` error path. The subtraction is now only performed after proving the digit is at least one, so the underflow and invalid index are eliminated.

## Residual Risk

None

## Patch

```diff
diff --git a/library/test/src/term/terminfo/parm.rs b/library/test/src/term/terminfo/parm.rs
index 529ec0c36e4..581744a98da 100644
--- a/library/test/src/term/terminfo/parm.rs
+++ b/library/test/src/term/terminfo/parm.rs
@@ -275,8 +275,8 @@ pub(crate) fn expand(
                 // params are 1-indexed
                 stack.push(
                     mparams[match cur.to_digit(10) {
-                        Some(d) => d as usize - 1,
-                        None => return Err("bad param number".to_string()),
+                        Some(d @ 1..=9) => d as usize - 1,
+                        _ => return Err("bad param number".to_string()),
                     }]
                     .clone(),
                 );
```