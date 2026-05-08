# KeyNote assertion signature check verifies wrong buffer

## Classification

High severity security control failure.

Confidence: certain.

## Affected Locations

`sbin/isakmpd/policy.c:2031`

## Summary

`keynote_cert_validate()` decomposes a received KeyNote credential payload into individual assertions, but verifies the original credential buffer for every parsed assertion instead of verifying the current parsed assertion. A multi-assertion payload can therefore pass validation based on the same repeated check while later assertions are not individually signature-verified. `keynote_cert_insert()` then re-parses the same payload and inserts every assertion into the policy session.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

KeyNote policy is enabled and peer credentials are accepted for validation.

## Proof

- `keynote_cert_validate()` calls `kn_read_asserts((char *)scert, strlen((char *)scert), &num)` to split the credential payload into `foo[num]`.
- The validation loop iterates over each parsed assertion with `for (i = 0; i < num; i++)`.
- Before the patch, each iteration called `kn_verify_assertion(scert, strlen((char *)scert))`.
- The current assertion `foo[i]` was not passed to `kn_verify_assertion()`.
- A practical trigger is a KeyNote CERT payload containing multiple blank-line-separated assertions where the first assertion verifies successfully and a later assertion has a bad or missing signature.
- Because the same original buffer was re-verified for each `foo[i]`, the bad later assertion did not affect the validation result.
- After validation, `keynote_cert_insert()` re-splits the same payload and calls `kn_add_assertion(sid, foo[num], strlen(foo[num]), 0)` for every parsed assertion.

## Why This Is A Real Bug

The function comment states that received credentials are signature-verified and that the whole payload is dropped on signature failure. The implementation violated that contract by applying the verification result for the original buffer to every parsed assertion. Since insertion later adds each parsed assertion independently, assertions that were never individually accepted by the signature validator could enter the KeyNote policy engine.

## Fix Requirement

Call `kn_verify_assertion()` on each parsed assertion buffer, `foo[i]`, before allowing validation to succeed and before later insertion can add those assertions to the policy session.

## Patch Rationale

The patch changes the verification input from the original credential buffer to the current parsed assertion:

```c
kn_verify_assertion(foo[i], strlen(foo[i]))
```

This aligns the validation loop with the parser output and ensures every assertion returned by `kn_read_asserts()` must independently produce `SIGRESULT_TRUE`. Existing failure cleanup and all-or-nothing payload rejection behavior are preserved.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/isakmpd/policy.c b/sbin/isakmpd/policy.c
index d76f390..6fd50b5 100644
--- a/sbin/isakmpd/policy.c
+++ b/sbin/isakmpd/policy.c
@@ -2031,7 +2031,7 @@ keynote_cert_validate(void *scert)
 		return 0;
 
 	for (i = 0; i < num; i++) {
-		if (kn_verify_assertion(scert, strlen((char *)scert))
+		if (kn_verify_assertion(foo[i], strlen(foo[i]))
 		    != SIGRESULT_TRUE) {
 			for (; i < num; i++)
 				free(foo[i]);
```