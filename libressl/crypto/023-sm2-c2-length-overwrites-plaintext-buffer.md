# SM2 C2 length overwrites plaintext buffer

## Classification

Out-of-bounds write. Severity: high. Confidence: certain.

## Affected Locations

`sm2/sm2_crypt.c:577`

## Summary

`SM2_decrypt()` trusts the attacker-controlled ASN.1 `C2` OCTET STRING length as the plaintext length and writes that many bytes into the caller-provided plaintext buffer. The function does not verify that `sm2_ctext->C2->length` is less than or equal to the caller-supplied `*ptext_len` capacity before the plaintext recovery loop.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Caller decrypts attacker-supplied SM2 ciphertext into a fixed plaintext buffer and passes that buffer capacity in `*ptext_len`.

## Proof

`SM2_decrypt()` decodes attacker-controlled ASN.1 with `d2i_SM2_Ciphertext()` and assigns:

```c
msg_len = sm2_ctext->C2->length;
```

Before the patch, `msg_len` was not compared against `*ptext_len`. The plaintext recovery loop then wrote:

```c
for (i = 0; i != msg_len; ++i)
	ptext_buf[i] = C2[i] ^ msg_mask[i];
```

Concrete trigger: caller supplies `ptext_buf[16]` with `*ptext_len = 16`; remote peer sends DER SM2 ciphertext with `C2` OCTET STRING length 64. The loop writes `ptext_buf[16]` through `ptext_buf[63]`, corrupting memory past the caller buffer.

The write occurs before C3 verification, so an invalid authentication tag does not prevent memory corruption.

## Why This Is A Real Bug

`*ptext_len` is used as the caller buffer capacity earlier in `SM2_decrypt()` for:

```c
memset(ptext_buf, 0xFF, *ptext_len);
```

This establishes that the function expects `*ptext_len` to describe writable output capacity. However, the subsequent write length is controlled by ASN.1 `C2->length`, which is attacker-supplied. If `C2->length > *ptext_len`, the plaintext recovery loop writes out of bounds.

The EVP path does not block the issue because `pkey_sm2_decrypt()` calls `SM2_decrypt()` directly when `out != NULL`.

## Fix Requirement

Reject ciphertexts where `sm2_ctext->C2->length` exceeds the caller-provided plaintext buffer capacity before allocating masks or writing to `ptext_buf`.

## Patch Rationale

The patch adds a bounds check immediately after decoding `C2` and assigning `msg_len`:

```c
if ((size_t)msg_len > *ptext_len) {
	SM2error(SM2_R_INVALID_ENCODING);
	goto err;
}
```

This preserves existing control flow, reports invalid ciphertext encoding, and prevents the plaintext recovery loop from writing past the caller buffer.

## Residual Risk

None

## Patch

```diff
diff --git a/sm2/sm2_crypt.c b/sm2/sm2_crypt.c
index 3bc1f21..f85eef6 100644
--- a/sm2/sm2_crypt.c
+++ b/sm2/sm2_crypt.c
@@ -507,6 +507,10 @@ SM2_decrypt(const EC_KEY *key, const EVP_MD *digest, const uint8_t *ciphertext,
 	C2 = sm2_ctext->C2->data;
 	C3 = sm2_ctext->C3->data;
 	msg_len = sm2_ctext->C2->length;
+	if ((size_t)msg_len > *ptext_len) {
+		SM2error(SM2_R_INVALID_ENCODING);
+		goto err;
+	}
 
 	if ((ctx = BN_CTX_new()) == NULL) {
 		SM2error(ERR_R_MALLOC_FAILURE);
```