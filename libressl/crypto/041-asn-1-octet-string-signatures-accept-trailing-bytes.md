# ASN.1 OCTET STRING Signatures Accept Trailing Bytes

## Classification

security_control_failure, high severity, certain confidence.

## Affected Locations

`rsa/rsa_saos.c:122`

## Summary

`RSA_verify_ASN1_OCTET_STRING` accepts decrypted signature payloads that contain a valid ASN.1 `OCTET STRING` followed by extra trailing bytes. The verifier decodes the leading `OCTET STRING` and compares its contents to the expected message, but it does not require the ASN.1 decoder to consume the entire decrypted payload.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

A caller verifies attacker-supplied signature bytes using `RSA_verify_ASN1_OCTET_STRING`.

## Proof

`RSA_verify_ASN1_OCTET_STRING` first checks only that the raw signature length equals `RSA_size(rsa)` at `rsa/rsa_saos.c:114`. After `RSA_public_decrypt`, it sets `p = s` and calls:

```c
sig = d2i_ASN1_OCTET_STRING(NULL, &p, (long)i);
```

The ASN.1 decoder advances `p` past the parsed `OCTET STRING`, but it does not require full consumption of the input buffer. The verifier then checks only:

```c
(unsigned int)sig->length == m_len
timingsafe_bcmp(m, sig->data, m_len) == 0
```

If the decoded `OCTET STRING` contents match `m`, `ret = 1` is reached even when `p != s + i`.

A decrypted payload of the form:

```text
DER(OCTET STRING(m)) || trailing_bytes
```

is therefore accepted as a valid signature.

## Why This Is A Real Bug

The verifier is intended to validate the DER-encoded ASN.1 `OCTET STRING` carried by the RSA signature. DER is a single-object encoding for this verifier contract; accepting additional bytes after the decoded object permits malformed encoded signatures to pass verification.

This is a deterministic fail-open behavior in a signature verification path: an attacker-controlled signature can contain a correctly decoded `OCTET STRING` plus arbitrary trailing bytes and still be accepted.

## Fix Requirement

After `d2i_ASN1_OCTET_STRING`, reject the signature unless the decoder consumed exactly all decrypted payload bytes:

```c
p == s + i
```

## Patch Rationale

The patch adds the missing full-consumption check immediately after ASN.1 decoding:

```diff
-	if (sig == NULL)
+	if (sig == NULL || p != s + i)
 		goto err;
```

This preserves existing rejection behavior for decode failures and extends it to malformed payloads with trailing bytes. Valid signatures are unaffected because valid DER-encoded `OCTET STRING` payloads leave `p` exactly at `s + i`.

## Residual Risk

None

## Patch

```diff
diff --git a/rsa/rsa_saos.c b/rsa/rsa_saos.c
index 3052fa9..73fc5b1 100644
--- a/rsa/rsa_saos.c
+++ b/rsa/rsa_saos.c
@@ -128,7 +128,7 @@ RSA_verify_ASN1_OCTET_STRING(int dtype, const unsigned char *m,
 
 	p = s;
 	sig = d2i_ASN1_OCTET_STRING(NULL, &p, (long)i);
-	if (sig == NULL)
+	if (sig == NULL || p != s + i)
 		goto err;
 
 	if ((unsigned int)sig->length != m_len ||
```