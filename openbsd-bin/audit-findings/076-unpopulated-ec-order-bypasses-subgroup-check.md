# Unpopulated EC Order Bypasses Subgroup Check

## Classification

security_control_failure, high severity, confidence certain

## Affected Locations

`usr.bin/ssh/sshkey.c:2571`

## Summary

`sshkey_ec_validate_public()` intends to reject EC public points outside the correct subgroup when the curve cofactor is not one. In that branch, it allocated `order` but did not populate it before passing it to `EC_POINT_mul()`. The subgroup test therefore computed `0 * Q`, which is infinity for any non-infinity point, causing invalid subgroup points to be accepted.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- A caller invokes `sshkey_ec_validate_public()` with an EC group whose cofactor is not one.
- The supplied public point is non-infinity and otherwise reaches the subgroup membership branch.

## Proof

- `sshkey_ec_validate_public()` fetches the curve cofactor and skips subgroup validation only when the cofactor is one.
- For non-one cofactors, it allocates `order` with `BN_new()` but, before the patch, never calls `EC_GROUP_get_order()`.
- The unpopulated `order` is passed to `EC_POINT_mul(group, nq, NULL, public, order, NULL)`.
- Because the fresh `BIGNUM` represents zero, the code computes `0 * Q`, producing infinity.
- The validator treats `nQ == infinity` as success and returns `0`.
- Reproduction confirmed this with an OpenSSL PoC using a cofactor-2 toy curve: a point with real `order * Q != infinity` was accepted by the vulnerable logic and rejected after populating `order`.

## Why This Is A Real Bug

The function implements an explicit subgroup membership security check. For cofactor-nonone curves, accepting points outside the subgroup defeats that check and can expose callers to invalid-subgroup public keys. The behavior is deterministic: the vulnerable branch uses a zero scalar instead of the subgroup order, so the test fails open whenever the branch is reached.

## Fix Requirement

Populate `order` with `EC_GROUP_get_order(group, order, NULL)` before using it in `EC_POINT_mul()`, and reject if retrieving the order fails.

## Patch Rationale

The patch initializes the subgroup order immediately after allocating `order` and before allocating/using `nq`. If OpenSSL cannot provide the group order, the function returns `SSH_ERR_LIBCRYPTO_ERROR`. This makes the subsequent multiplication compute the intended `order * public` subgroup test instead of `0 * public`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ssh/sshkey.c b/usr.bin/ssh/sshkey.c
index 2a0c33c..86ef6b3 100644
--- a/usr.bin/ssh/sshkey.c
+++ b/usr.bin/ssh/sshkey.c
@@ -2669,6 +2669,10 @@ sshkey_ec_validate_public(const EC_GROUP *group, const EC_POINT *public)
 			ret = SSH_ERR_ALLOC_FAIL;
 			goto out;
 		}
+		if (EC_GROUP_get_order(group, order, NULL) != 1) {
+			ret = SSH_ERR_LIBCRYPTO_ERROR;
+			goto out;
+		}
 		if ((nq = EC_POINT_new(group)) == NULL) {
 			ret = SSH_ERR_ALLOC_FAIL;
 			goto out;
```