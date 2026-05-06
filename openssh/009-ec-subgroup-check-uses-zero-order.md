# EC subgroup check uses zero order

## Classification

security_control_failure; defense-in-depth (low severity for OpenSSH today); confidence certain.

## Affected Locations

`sshkey.c:2638` (`sshkey_ec_validate_public`, the cofactor>1 branch starting around line 2667)

## Summary

`sshkey_ec_validate_public` intends to reject EC public points outside the subgroup when the curve cofactor is greater than one. In that branch, it allocated `order` with `BN_new()` but did not populate it with `EC_GROUP_get_order()`. The subsequent scalar multiplication used zero as the subgroup order, causing the subgroup check to pass for invalid points.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

The caller validates an EC group whose cofactor is greater than one.

## Proof

The vulnerable path is deterministic:

- `sshkey_ec_validate_public` rejects infinity and reads the group cofactor.
- For `cofactor > 1`, it allocates `order` with `BN_new()`.
- The original code never called `EC_GROUP_get_order(group, order, NULL)`.
- `EC_POINT_mul(group, nq, NULL, public, order, NULL)` therefore computed `0 * public`.
- The result is infinity, so `EC_POINT_is_at_infinity(group, nq)` succeeds.
- The function reaches `ret = 0`, accepting a non-infinity, on-curve point outside the subgroup.

A minimal OpenSSL harness using a small cofactor-6 curve confirmed the behavior: a point `Q` for which the real subgroup order gives `nQ != infinity` was accepted by the committed logic because `order` remained zero. Adding `EC_GROUP_get_order()` caused the same point to be rejected.

## Why This Is A Real Bug

The function is the EC public-key subgroup validation control. For curves with cofactor greater than one, subgroup membership requires checking that multiplication by the subgroup order yields infinity. Multiplying by an uninitialized zero-valued `BIGNUM` does not test subgroup membership; it forces the result to infinity and makes the validator fail open.

Practical reachability in OpenSSH is limited: the only EC curves built into OpenSSH are NIST P-256, P-384, and P-521, all of which have cofactor 1, so the buggy `if (!BN_is_one(cofactor))` branch is dead code through every supported call site. The fix is therefore a correctness/defense-in-depth change rather than a presently exploitable vulnerability — but it removes a fail-open primitive that would silently bless any future cofactor>1 curve added to the build.

## Fix Requirement

Before calling `EC_POINT_mul`, populate `order` with `EC_GROUP_get_order(group, order, NULL)` and treat failure as a libcrypto error.

## Patch Rationale

The patch loads the actual subgroup order into `order` immediately after allocation and before constructing `nq` or performing scalar multiplication. This restores the intended `nQ == infinity` validation and preserves existing error handling by returning `SSH_ERR_LIBCRYPTO_ERROR` if OpenSSL cannot provide the group order.

## Residual Risk

None

## Patch

```diff
diff --git a/sshkey.c b/sshkey.c
index 2a0c33c..86ef6b3 100644
--- a/sshkey.c
+++ b/sshkey.c
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