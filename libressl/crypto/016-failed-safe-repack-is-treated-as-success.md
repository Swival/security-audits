# Failed Safe Repack Is Treated As Success

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`pkcs12/p12_npas.c:276`

## Summary

`PKCS12_newpass()` inverted the success checks for both safe repack helpers. A failed safe repack was allowed to continue, leaving the failed safe out of the replacement `safes` stack. `pkcs12_repack_authsafes()` could then repack and MAC the incomplete stack, returning success with PKCS12 contents removed.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Victim invokes `PKCS12_newpass()` on an attacker-supplied PKCS12 object that has a valid MAC.

## Proof

A valid-MAC PKCS12 can contain a syntactically valid data safe whose `SAFEBAGS` decode succeeds but whose `pkcs8ShroudedKeyBag` cannot be decrypted with the old password.

Execution path:

- `PKCS12_newpass()` accepts the object after `PKCS12_verify_mac(pkcs12, oldpass, -1)` succeeds.
- For `NID_pkcs7_data`, `pkcs7_repack_data()` unpacks the safe with `PKCS12_unpack_p7data()`.
- `newpass_bags()` calls `newpass_bag()` for each bag.
- For `NID_pkcs8ShroudedKeyBag`, `newpass_bag()` calls `PKCS8_decrypt(bag->value.shkeybag, oldpass, -1)`.
- If that decrypt fails, `newpass_bag()` returns `0`, propagating failure through `newpass_bags()` and `pkcs7_repack_data()`.
- Because the original caller used `if (pkcs7_repack_data(...)) goto err;`, helper failure `0` was treated as success.
- The failed safe was never pushed into `safes`.
- `pkcs12_repack_authsafes()` then packed the incomplete `safes` stack, regenerated the MAC, and allowed `PKCS12_newpass()` to return `1`.

The same inverted check existed for `pkcs7_repack_encdata()`.

## Why This Is A Real Bug

The helper functions use conventional C boolean return semantics:

- `pkcs7_repack_data()` initializes `ret = 0` and sets `ret = 1` only after successfully pushing the replacement safe.
- `pkcs7_repack_encdata()` follows the same pattern.
- All internal failure paths return `0`.

`PKCS12_newpass()` reversed that contract. Success caused an error exit, while failure continued. This allows attacker-controlled input to make password-change output silently omit safe contents while still producing a valid MAC and success return.

If the caller persists the returned PKCS12 after a successful password change, credentials or other safe contents can be lost.

## Fix Requirement

Treat repack helper return values as boolean success indicators and abort when either helper returns `0`.

Required logic:

```c
if (!pkcs7_repack_data(pkcs7, safes, oldpass, newpass))
	goto err;

if (!pkcs7_repack_encdata(pkcs7, safes, oldpass, newpass))
	goto err;
```

## Patch Rationale

The patch aligns `PKCS12_newpass()` with the established return contract of both repack helpers. A safe is now considered successfully processed only if the helper returns `1`, which occurs after the replacement safe has been packed and pushed into the new `safes` stack.

This prevents `pkcs12_repack_authsafes()` from being called after a safe repack failure and avoids producing a valid-MAC PKCS12 with missing contents.

## Residual Risk

None

## Patch

```diff
diff --git a/pkcs12/p12_npas.c b/pkcs12/p12_npas.c
index c78deb9..ef1d218 100644
--- a/pkcs12/p12_npas.c
+++ b/pkcs12/p12_npas.c
@@ -276,11 +276,11 @@ PKCS12_newpass(PKCS12 *pkcs12, const char *oldpass, const char *newpass)
 
 		switch (OBJ_obj2nid(pkcs7->type)) {
 		case NID_pkcs7_data:
-			if (pkcs7_repack_data(pkcs7, safes, oldpass, newpass))
+			if (!pkcs7_repack_data(pkcs7, safes, oldpass, newpass))
 				goto err;
 			break;
 		case NID_pkcs7_encrypted:
-			if (pkcs7_repack_encdata(pkcs7, safes, oldpass, newpass))
+			if (!pkcs7_repack_encdata(pkcs7, safes, oldpass, newpass))
 				goto err;
 			break;
 		}
```