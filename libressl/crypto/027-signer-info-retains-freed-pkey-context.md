# signer info retains freed pkey context

## Classification

Memory corruption: use-after-free.

Severity: medium.

Confidence: certain.

## Affected Locations

`cms/cms_sd.c:936`

Related code paths:

`cms/cms_sd.c:487`

`cms/cms_sd.c:946`

`cms/cms_sd.c:953`

`cms/cms_sd.c:956`

`cms/cms_sd.c:965`

## Summary

`CMS_SignerInfo_verify_content()` stores a locally owned `EVP_PKEY_CTX *pkctx` in `si->pctx` when verifying CMS `SignerInfo` content without `signedAttrs`.

The function then always frees `pkctx` during cleanup, but previously left `si->pctx` pointing at the freed object. Applications that verify attacker-controlled CMS `SignedData` and later call `CMS_SignerInfo_get0_pkey_ctx()` can receive and use a dangling pointer.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the verified report and supplied source/patch evidence.

## Preconditions

- A remote peer or attacker can provide CMS `SignedData`.
- The attacker supplies a `SignerInfo` that omits `signedAttrs`.
- The application verifies the CMS content.
- The application later queries or uses `si->pctx`, for example via `CMS_SignerInfo_get0_pkey_ctx()`.

## Proof

For `SignerInfo` objects without `signedAttrs`, `CMS_SignerInfo_verify_content()` follows the no-attributes branch:

- `CMS_signed_get_attr_count(si)` indicates no signed attributes, so no `messageDigest` attribute is used.
- The function allocates `pkctx` with `EVP_PKEY_CTX_new(si->pkey, NULL)`.
- It initializes verification with `EVP_PKEY_verify_init(pkctx)`.
- It configures the signature digest with `EVP_PKEY_CTX_set_signature_md(pkctx, md)`.
- It assigns the local context to the signer info with `si->pctx = pkctx`.
- It verifies with `EVP_PKEY_verify(pkctx, ...)`.
- Cleanup always calls `EVP_PKEY_CTX_free(pkctx)`.

Before the patch, cleanup did not clear `si->pctx`. Therefore, after return, `CMS_SignerInfo_get0_pkey_ctx()` returned a pointer to freed heap memory.

## Why This Is A Real Bug

This is a real lifetime violation because ownership of `pkctx` remains local to `CMS_SignerInfo_verify_content()`: the function frees it unconditionally before returning.

At the same time, the public object field `si->pctx` is made to alias that local context. Since `CMS_SignerInfo_get0_pkey_ctx()` returns `si->pctx` directly, callers can observe and use a freed `EVP_PKEY_CTX`.

The trigger is attacker-controlled under the stated precondition because omitting `signedAttrs` in CMS `SignedData` selects the vulnerable branch. The impact is an attacker-triggered memory-safety failure or denial of service when an application later uses the dangling context through normal public APIs.

## Fix Requirement

The signer info must not retain a pointer to a locally owned `EVP_PKEY_CTX` after that context is freed.

Acceptable fixes include:

- Keep `pkctx` purely local and never store it in `si->pctx`.
- Clear `si->pctx` before freeing `pkctx` when `si->pctx` aliases the local context.

## Patch Rationale

The patch clears `si->pctx` only when it still points to the local `pkctx` that is about to be freed:

```c
if (si->pctx == pkctx)
	si->pctx = NULL;
EVP_PKEY_CTX_free(pkctx);
```

This preserves existing behavior during verification, where `si->pctx` is temporarily needed by `cms_sd_asn1_ctrl(si, 1)`, while preventing the `CMS_SignerInfo` from retaining a dangling pointer after cleanup.

The equality check avoids clearing `si->pctx` if another code path has changed it to a different context.

## Residual Risk

None

## Patch

```diff
diff --git a/cms/cms_sd.c b/cms/cms_sd.c
index abcac83..33244d9 100644
--- a/cms/cms_sd.c
+++ b/cms/cms_sd.c
@@ -962,6 +962,8 @@ CMS_SignerInfo_verify_content(CMS_SignerInfo *si, BIO *chain)
 	}
 
  err:
+	if (si->pctx == pkctx)
+		si->pctx = NULL;
 	EVP_PKEY_CTX_free(pkctx);
 	EVP_MD_CTX_free(mctx);
```