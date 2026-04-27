# unchecked division by zero

## Classification

error-handling bug; medium severity; confidence: certain.

## Affected Locations

`library/test/src/term/terminfo/parm.rs:192`

## Summary

Parameterized terminfo capability expansion panics when evaluating `%/` or `%m` with a zero divisor. The code pops `y` and `x` from the stack and evaluates `x / y` or `x % y` without checking `y == 0`, so malformed or malicious terminfo data can trigger a Rust divide-by-zero panic during normal capability expansion.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A terminfo capability contains division or modulo with a zero top stack value, for example `%{1}%{0}%/` or `%{1}%{0}%m`.

## Proof

- `expand` parses raw capability bytes and supports integer constants via `%{...}`.
- `%{0}` pushes `Number(0)` onto the stack.
- In percent handling, `%/` and `%m` pop `y` first, then `x`, and evaluate `x / y` or `x % y`.
- There is no zero-divisor check before the arithmetic in `library/test/src/term/terminfo/parm.rs:192`.
- A harness calling `expand(b"%{1}%{0}%/", &[], &mut Variables::new())` panics with `attempt to divide by zero` instead of returning `Err`.
- The path is reachable through normal terminfo expansion: `TerminfoTerminal::apply_cap` calls `expand` on terminfo string capabilities, and parsed compiled terminfo strings are stored without validating parameter expressions.

## Why This Is A Real Bug

Rust integer division and remainder by zero panic at runtime. `expand` is a fallible parser/evaluator returning `Result<Vec<u8>, String>`, and nearby malformed inputs already return `Err` for empty stack, bad constants, bad variables, and invalid format specifiers. A zero divisor is another malformed capability expression and should be handled as an error, not as a process panic. Because terminfo capabilities can be loaded from malformed or malicious entries, this creates a practical denial-of-service path during terminal capability expansion.

## Fix Requirement

Before evaluating `/` or `m`, check whether the divisor `y` is zero. If it is zero, return `Err` instead of performing the arithmetic.

## Patch Rationale

The patch adds a guarded match arm before the arithmetic arm:

```rust
(Some(Number(0)), Some(Number(_))) if cur == '/' || cur == 'm' => {
    return Err("division by zero".to_string());
}
```

This preserves existing behavior for all non-dividing operators and for valid nonzero division/modulo. It also preserves existing stack-pop semantics while converting the panic case into the function’s existing error-reporting mechanism.

## Residual Risk

None

## Patch

```diff
diff --git a/library/test/src/term/terminfo/parm.rs b/library/test/src/term/terminfo/parm.rs
index 529ec0c36e4..df7b5c64a64 100644
--- a/library/test/src/term/terminfo/parm.rs
+++ b/library/test/src/term/terminfo/parm.rs
@@ -185,6 +185,9 @@ pub(crate) fn expand(
                     },
                     '+' | '-' | '/' | '*' | '^' | '&' | '|' | 'm' => {
                         match (stack.pop(), stack.pop()) {
+                            (Some(Number(0)), Some(Number(_))) if cur == '/' || cur == 'm' => {
+                                return Err("division by zero".to_string());
+                            }
                             (Some(Number(y)), Some(Number(x))) => stack.push(Number(match cur {
                                 '+' => x + y,
                                 '-' => x - y,
```