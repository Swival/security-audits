# unchecked modulo by zero

## Classification

error-handling bug, medium severity

## Affected Locations

`library/test/src/term/terminfo/parm.rs:196`

## Summary

`expand` handles terminfo arithmetic operators by popping two numeric operands from a stack and evaluating the requested operation. For `%m`, it computes `x % y` without checking whether `y` is zero. A malformed or hostile terminfo capability can therefore panic the process instead of returning `Err`.

The same unchecked zero-divisor pattern also affects `%/`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A terminfo capability is expanded by `expand`.
- The capability uses `%m` after pushing zero as the second operand.
- Example capability bytes: `b"%{1}%{0}%m"`.

## Proof

The reproduced trigger is `b"%{1}%{0}%m"`.

Execution path:

- `%{1}` pushes `Number(1)` onto the stack.
- `%{0}` pushes `Number(0)` onto the stack.
- `%m` enters the binary-operator arm at `library/test/src/term/terminfo/parm.rs:186`.
- The stack pop binds `y = 0` and `x = 1`.
- `library/test/src/term/terminfo/parm.rs:196` evaluates `x % y`.

Runtime evidence from a harness calling:

```rust
expand(b"%{1}%{0}%m", &[], &mut Variables::new())
```

The committed code panics with:

```text
attempt to calculate the remainder with a divisor of zero
```

Reachability is through terminfo strings parsed into `TermInfo.strings` and passed to `expand` by `TerminfoTerminal::apply_cap` at `library/test/src/term/terminfo/mod.rs:184` and `reset` at `library/test/src/term/terminfo/mod.rs:148`.

## Why This Is A Real Bug

The function already treats malformed parameterized capabilities as recoverable errors in nearby cases, including stack underflow and invalid constants. A zero divisor is another malformed arithmetic expression and should be returned as `Err`, not allowed to trigger Rust's runtime panic.

Because terminfo capabilities can be malformed or hostile, this creates a denial-of-service condition for any caller that expands such a capability.

## Fix Requirement

Before evaluating division or modulo, check whether the divisor is zero. If it is zero, return `Err` instead of evaluating the arithmetic expression.

Required behavior:

- `%/` with divisor zero returns `Err("division by zero")`.
- `%m` with divisor zero returns `Err("modulo by zero")`.
- Existing arithmetic behavior is preserved for nonzero divisors.

## Patch Rationale

The patch adds guarded match arms for `/` and `m` in the binary-operator handler:

- `'/ ' if y != 0 => x / y`
- `'/' => return Err("division by zero".to_string())`
- `'m' if y != 0 => x % y`
- `'m' => return Err("modulo by zero".to_string())`

This keeps the existing stack-pop structure and arithmetic dispatch intact while preventing both zero-divisor panic paths.

## Residual Risk

None

## Patch

```diff
diff --git a/library/test/src/term/terminfo/parm.rs b/library/test/src/term/terminfo/parm.rs
index 529ec0c36e4..4adfba1f4ad 100644
--- a/library/test/src/term/terminfo/parm.rs
+++ b/library/test/src/term/terminfo/parm.rs
@@ -189,11 +189,13 @@ pub(crate) fn expand(
                                 '+' => x + y,
                                 '-' => x - y,
                                 '*' => x * y,
-                                '/' => x / y,
+                                '/' if y != 0 => x / y,
+                                '/' => return Err("division by zero".to_string()),
                                 '|' => x | y,
                                 '&' => x & y,
                                 '^' => x ^ y,
-                                'm' => x % y,
+                                'm' if y != 0 => x % y,
+                                'm' => return Err("modulo by zero".to_string()),
                                 _ => unreachable!("All cases handled"),
                             })),
                             _ => return Err("stack is empty".to_string()),
```