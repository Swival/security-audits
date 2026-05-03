# Signed Division Overflow In `#if` Evaluator

## Classification

Denial of service, medium severity.

## Affected Locations

`tradcpp/eval.c:443`

## Summary

The `#if` expression evaluator can execute signed integer division overflow when reducing `INT_MIN / -1`. An attacker-controlled source file can trigger undefined behavior during preprocessing, causing a UBSan abort or a crash on trapping integer division implementations.

## Provenance

Verified from source and reproduced from the reported finding.

Source: Swival Security Scanner, https://swival.dev

Confidence: certain.

## Preconditions

The preprocessor evaluates attacker-controlled `#if` expressions.

## Proof

A malicious source file can contain:

```c
#if (-2147483647 - 1) / -1
#endif
```

Reachability and propagation:

- `d_if()` evaluates top-level `#if` expressions when the current conditional state is true at `tradcpp/directive.c:197`.
- `wordval()` accepts `2147483647`.
- Unary `-` reduces this to `-2147483647`.
- `eval_bop(T_MINUS)` reduces `-2147483647 - 1` to `INT_MIN`.
- `tryreduce()` then reduces the division by calling `eval_bop()` with `lv == INT_MIN`, `op == T_SLASH`, and `rv == -1`.
- The `T_SLASH` case only checked `rv == 0`, then executed `lv / rv`, reaching C signed division overflow.

The affected operation is in `tradcpp/eval.c`, in the `T_SLASH` branch of `eval_bop()`.

## Why This Is A Real Bug

C signed division overflow is undefined behavior for `INT_MIN / -1`. The evaluator already contains explicit overflow handling for other arithmetic operators, including subtraction and multiplication, showing that overflow is expected to be detected and reported rather than executed.

Because `#if` expressions can come from attacker-controlled source files, this undefined behavior is externally triggerable. In UBSan builds it aborts at runtime; on platforms where integer division traps, it can crash the preprocessor. This is a denial-of-service condition.

## Fix Requirement

Reject or otherwise handle `INT_MIN / -1` before performing signed division.

## Patch Rationale

The patch adds a guard in the `T_SLASH` case immediately after the existing division-by-zero check and before `lv / rv`.

When `rv == -1 && lv == INT_MIN`, the evaluator now:

- reports `Integer overflow`;
- marks evaluation failure with `complain_fail()`;
- returns `INT_MAX`, matching the existing overflow-saturation behavior used elsewhere in `eval_bop()`.

This prevents undefined behavior while preserving the evaluator’s existing diagnostic style.

## Residual Risk

None

## Patch

```diff
diff --git a/tradcpp/eval.c b/tradcpp/eval.c
index 6a6bcad..2514277 100644
--- a/tradcpp/eval.c
+++ b/tradcpp/eval.c
@@ -409,6 +409,11 @@ eval_bop(struct place *p, int lv, enum tokens op, int rv)
 			complain_fail();
 			return 0;
 		}
+		if (rv == -1 && lv == INT_MIN) {
+			complain(p, "Integer overflow");
+			complain_fail();
+			return INT_MAX;
+		}
 		return lv / rv;
 
 	    case T_PCT:
```