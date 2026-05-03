# signed remainder overflow in #if evaluator

## Classification

Denial of service, medium severity.

## Affected Locations

`tradcpp/eval.c:452`

## Summary

`tradcpp` evaluates attacker-controlled `#if` expressions using signed `int` arithmetic. The remainder operator path rejects only modulus by zero before executing `lv % rv`. A crafted expression can make `lv == INT_MIN` and `rv == -1`, which is undefined behavior in C because the implied quotient is not representable. Hardened builds can abort, producing a preprocessing denial of service.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A source file is preprocessed by `tradcpp`.
- The source file author can control a `#if` expression.

## Proof

A malicious source file can include:

```c
#if (0-2147483647-1)%-1
#endif
```

The expression is accepted by the evaluator:

- `#if` directives are macro-expanded and passed to `eval()` from `tradcpp/directive.c:190` and `tradcpp/directive.c:198`.
- `wordval()` accepts `2147483647` and `1` as valid integer constants.
- Left-associative `T_MINUS` reductions in `eval_bop()` compute the representable value `INT_MIN` from `(0-2147483647-1)`.
- The `T_PCT` branch checks only `rv == 0`, then evaluates `lv % rv`.
- With `lv == INT_MIN` and `rv == -1`, C signed remainder has undefined behavior.

Runtime evidence confirmed the crash path: building the committed source with UBSan and preprocessing the crafted input aborts with:

```text
runtime error: division of -2147483648 by -1 cannot be represented in type 'int'
```

reported at `tradcpp/eval.c:420`.

## Why This Is A Real Bug

C defines signed division and remainder overflow as undefined behavior when the quotient is not representable. `INT_MIN / -1` and `INT_MIN % -1` both trigger this condition. Because `eval_bop()` can produce `INT_MIN` through valid token reductions and then directly evaluates `% -1`, an input file can crash the preprocessor during normal `#if` parsing.

## Fix Requirement

Before evaluating signed remainder, reject or special-case the `INT_MIN % -1` operand pair.

## Patch Rationale

The patch adds an explicit guard in the `T_PCT` branch:

```c
if (rv == -1 && lv == INT_MIN) {
	return 0;
}
```

This prevents the undefined signed remainder operation while preserving the mathematical result of any integer remainder by `-1`, which is `0`. The existing modulus-by-zero diagnostic remains unchanged.

## Residual Risk

None

## Patch

```diff
diff --git a/tradcpp/eval.c b/tradcpp/eval.c
index 6a6bcad..069b03d 100644
--- a/tradcpp/eval.c
+++ b/tradcpp/eval.c
@@ -419,6 +419,9 @@ eval_bop(struct place *p, int lv, enum tokens op, int rv)
 			complain_fail();
 			return 0;
 		}
+		if (rv == -1 && lv == INT_MIN) {
+			return 0;
+		}
 		return lv % rv;

 	    default: assert(0); break;
```