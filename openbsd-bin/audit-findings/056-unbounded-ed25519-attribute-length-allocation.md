# Unbounded Ed25519 Attribute Length Allocation

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`usr.bin/ssh/ssh-pkcs11.c:1207`

## Summary

`pkcs11_fetch_ed25519_pubkey()` trusted PKCS#11 provider-reported attribute lengths from the first `C_GetAttributeValue()` call and allocated buffers from those lengths before validating Ed25519-specific bounds. A token/backend that reports huge `CKA_EC_POINT`, `CKA_EC_PARAMS`, or `CKA_ID` lengths can force excessive allocation during SSH PKCS#11 key enumeration, causing memory exhaustion or fatal process termination.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

User loads an attacker-controlled PKCS#11 provider or token/backend.

## Proof

`pkcs11_fetch_keys()` dispatches `CKK_EC_EDWARDS` public-key objects to `pkcs11_fetch_ed25519_pubkey()`.

In `pkcs11_fetch_ed25519_pubkey()`, the first `C_GetAttributeValue(session, *obj, key_attr, 3)` is used to discover lengths for:

- `CKA_ID`
- `CKA_EC_POINT`
- `CKA_EC_PARAMS`

The original code rejected only zero lengths for `CKA_EC_POINT` and `CKA_EC_PARAMS`, then allocated every positive reported length:

```c
for (i = 0; i < 3; i++) {
	if (key_attr[i].ulValueLen > 0)
		key_attr[i].pValue = xcalloc(1, key_attr[i].ulValueLen);
}
```

Validation that `CKA_EC_PARAMS` is one of the supported Ed25519 identifiers, and validation that `CKA_EC_POINT` is either 32 bytes or a 34-byte OCTET STRING wrapper, happened only after allocation.

`xcalloc()` fatally exits on allocation failure, so a huge provider-reported length can terminate SSH or ssh-agent during PKCS#11 enumeration.

## Why This Is A Real Bug

The affected code consumes length metadata supplied through the PKCS#11 interface before applying the strict Ed25519 size constraints already implied by later parsing logic. The attack does not depend on arbitrary code execution by a malicious shared library; the in-scope trigger is attacker-controlled token/backend attribute metadata returned via `C_GetAttributeValue()`.

Because enumeration occurs when the provider/token is loaded, the failure is reachable before any private-key operation and can deny service by exhausting memory or triggering fatal allocation failure.

## Fix Requirement

Bound all Ed25519 attribute lengths before allocating buffers, and reject oversized values immediately after the initial length-discovery `C_GetAttributeValue()` call.

Required maximums:

- `CKA_ID`: bounded to a small implementation limit.
- `CKA_EC_POINT`: at most `ED25519_PK_SZ + 2`.
- `CKA_EC_PARAMS`: at most the longest supported Ed25519 identifier.

## Patch Rationale

The patch adds pre-allocation length checks after the existing nonzero checks and before the allocation loop:

```c
if (key_attr[0].ulValueLen > 1024 ||
    key_attr[1].ulValueLen > ED25519_PK_SZ + 2 ||
    key_attr[2].ulValueLen > sizeof(id1)) {
	error("invalid attribute length");
	return (NULL);
}
```

This preserves valid Ed25519 encodings while preventing attacker-controlled metadata from driving unbounded memory allocation.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ssh/ssh-pkcs11.c b/usr.bin/ssh/ssh-pkcs11.c
index e2bd8de..832bab2 100644
--- a/usr.bin/ssh/ssh-pkcs11.c
+++ b/usr.bin/ssh/ssh-pkcs11.c
@@ -1126,6 +1126,12 @@ pkcs11_fetch_ed25519_pubkey(struct pkcs11_provider *p, CK_ULONG slotidx,
 		error("invalid attribute length");
 		return (NULL);
 	}
+	if (key_attr[0].ulValueLen > 1024 ||
+	    key_attr[1].ulValueLen > ED25519_PK_SZ + 2 ||
+	    key_attr[2].ulValueLen > sizeof(id1)) {
+		error("invalid attribute length");
+		return (NULL);
+	}
 
 	/* allocate buffers for attributes */
 	for (i = 0; i < 3; i++) {
```