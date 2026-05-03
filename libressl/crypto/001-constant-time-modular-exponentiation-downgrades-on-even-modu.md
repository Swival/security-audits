# Constant-Time Modular Exponentiation Downgrades On Even Moduli

## Classification

Security control failure, high severity.

## Affected Locations

`bn/bn_exp.c:846`

`bn/bn_exp.c:1122`

## Summary

`BN_mod_exp_ct()` requests constant-time modular exponentiation, but `BN_mod_exp_internal()` routed even moduli to `BN_mod_exp_reciprocal()`. That reciprocal implementation is variable-time with exponent-dependent control flow and table indexing. As a result, explicit constant-time callers using an even modulus could receive a successful result from a non-constant-time path, leaking information about a secret exponent through timing.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Caller invokes `BN_mod_exp_ct()` with a secret exponent.
- The modulus `m` is even.
- The exponent passed to `BN_mod_exp_ct()` is not already marked with `BN_FLG_CONSTTIME`.

## Proof

`BN_mod_exp_ct()` calls `BN_mod_exp_internal(r, a, p, m, ctx, 1)`, setting the internal `ct` parameter.

Before the patch, `BN_mod_exp_internal()` selected the implementation only by modulus parity for even moduli:

```c
if (BN_is_odd(m)) {
	...
} else	{
	ret = BN_mod_exp_reciprocal(r, a,p, m, ctx);
}
```

Thus, for an even modulus, `ct == 1` still dispatched to `BN_mod_exp_reciprocal()`.

`BN_mod_exp_reciprocal()` only rejects when the exponent itself has `BN_FLG_CONSTTIME`; `BN_mod_exp_ct()` does not set that flag on `p`. Therefore, ordinary explicit constant-time callers with an unflagged secret exponent proceed through the reciprocal path and can reach successful completion.

The reciprocal path is exponent-dependent:

- It branches on copied exponent bits with `BN_is_bit_set(q, wstart)`.
- It scans secret-dependent windows with `BN_is_bit_set(q, wstart - i)`.
- It varies the number of squarings based on the selected window length.
- It indexes the precomputed table as `val[wvalue >> 1]`.

The true constant-time Montgomery path rejects even moduli, but the generic constant-time entry bypassed that guard by selecting the reciprocal implementation first.

## Why This Is A Real Bug

`BN_mod_exp_ct()` is a named constant-time API. A caller selecting it has requested a side-channel-resistant exponentiation path for secret exponents.

For odd moduli, the code reaches the constant-time Montgomery implementation. For even moduli, the same API silently downgraded to a variable-window reciprocal implementation and returned success. This is a fail-open behavior in a security control: the function did not preserve its constant-time contract and did not reject an unsupported modulus.

The leak is not theoretical because the reached code contains direct exponent-dependent branches, loop counts, window selection, and table accesses.

## Fix Requirement

Constant-time mode must not fall back to `BN_mod_exp_reciprocal()` for even moduli. It must either:

- reject even moduli in `ct` mode, or
- implement a constant-time even-modulus exponentiation algorithm.

## Patch Rationale

The patch rejects even moduli when `ct` is set inside `BN_mod_exp_internal()`:

```c
} else if (ct) {
	BNerror(BN_R_CALLED_WITH_EVEN_MODULUS);
	return (0);
} else	{
	ret = BN_mod_exp_reciprocal(r, a,p, m, ctx);
}
```

This preserves existing behavior for non-constant-time callers while preventing `BN_mod_exp_ct()` from silently entering the variable-time reciprocal implementation. The error matches the existing constant-time Montgomery rejection for even moduli.

## Residual Risk

None

## Patch

```diff
diff --git a/bn/bn_exp.c b/bn/bn_exp.c
index 6a5c1c8..959f3e9 100644
--- a/bn/bn_exp.c
+++ b/bn/bn_exp.c
@@ -1122,6 +1122,9 @@ BN_mod_exp_internal(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m
 			ret = BN_mod_exp_mont_word(r, A,p, m,ctx, NULL);
 		} else
 			ret = BN_mod_exp_mont_ct(r, a,p, m,ctx, NULL);
+	} else if (ct) {
+		BNerror(BN_R_CALLED_WITH_EVEN_MODULUS);
+		return (0);
 	} else	{
 		ret = BN_mod_exp_reciprocal(r, a,p, m, ctx);
 	}
```