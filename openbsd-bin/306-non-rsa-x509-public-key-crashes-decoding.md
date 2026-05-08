# non-RSA X509 public key crashes decoding

## Classification

Denial of service, medium severity.

## Affected Locations

`lib/libkeynote/signature.c:517`

## Summary

`kn_decode_key` accepts any syntactically valid X.509 certificate, extracts its public key, assumes the key is RSA, and calls `RSA_up_ref` on the result of `EVP_PKEY_get0_RSA` without checking for `NULL`. A non-RSA X.509 certificate, such as one containing an EC public key, causes a NULL dereference during assertion verification.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The target verifies untrusted KeyNote assertions containing X.509 public keys.

## Proof

During signature-verification parsing, `kn_verify_assertion` passes the attacker-controlled assertion buffer to `keynote_parse_assertion` with `ASSERT_FLAG_SIGVER`.

The reproduced path is:

- `lib/libkeynote/parse_assertion.c:630`: assertion authorizer is evaluated during signature-verification parsing.
- `lib/libkeynote/keynote.y:162`: authorizer parsing records the quoted key via `keynote_keylist_add`.
- `lib/libkeynote/auxil.c:152`: `keynote_keylist_add` calls `kn_decode_key`.
- `lib/libkeynote/signature.c:504`: X.509 decoding accepts any decoded certificate from `d2i_X509`.
- `lib/libkeynote/signature.c:512`: the code only checks that `X509_get0_pubkey` returns some public key.
- `lib/libkeynote/signature.c:520`: `EVP_PKEY_get0_RSA(pPublicKey)` returns `NULL` for a non-RSA certificate.
- `lib/libkeynote/signature.c:521`: `RSA_up_ref(dc->dec_key)` is called immediately, dereferencing `NULL`.

A harness using `kn_decode_key` with a generated EC X.509 certificate printed the failing call and then segfaulted with `status=139`. The same harness with an RSA X.509 certificate returned success.

## Why This Is A Real Bug

The X.509 verification path is explicitly RSA-specific elsewhere: decoded X.509 keys are freed as RSA keys, compared as RSA keys, and verified through RSA signature APIs. Therefore, accepting a non-RSA X.509 public key without rejecting it is invalid for the current implementation.

The crash occurs before the malformed assertion is rejected. A remote or peer-controlled assertion sender can terminate a verifier process by supplying an assertion authorizer containing a non-RSA X.509 certificate.

## Fix Requirement

Reject non-RSA X.509 public keys before calling `RSA_up_ref`, or add full support for non-RSA X.509 keys throughout decoding, comparison, freeing, and signature verification.

## Patch Rationale

The patch preserves the existing RSA-only X.509 implementation and adds the missing validation immediately after `EVP_PKEY_get0_RSA`.

If the certificate public key is not RSA, `kn_decode_key` now:

- frees the decoded input buffer,
- frees the X.509 certificate,
- sets `keynote_errno = ERROR_SYNTAX`,
- returns `-1`.

This turns the attacker-controlled crash into a normal parse failure.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/libkeynote/signature.c b/lib/libkeynote/signature.c
index d4123ca..a9b9086 100644
--- a/lib/libkeynote/signature.c
+++ b/lib/libkeynote/signature.c
@@ -518,6 +518,12 @@ kn_decode_key(struct keynote_deckey *dc, char *key, int keytype)
 
 	/* RSA-specific */
 	dc->dec_key = EVP_PKEY_get0_RSA(pPublicKey);
+	if (dc->dec_key == NULL) {
+	    free(ptr);
+	    X509_free(px509Cert);
+	    keynote_errno = ERROR_SYNTAX;
+	    return -1;
+	}
 	RSA_up_ref(dc->dec_key);
 
 	free(ptr);
```