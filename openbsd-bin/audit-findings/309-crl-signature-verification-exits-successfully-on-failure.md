# CRL signature verification exits successfully on failure

## Classification

Security control failure, high severity. Confidence: certain.

## Affected Locations

`usr.bin/openssl/crl.c:329`

## Summary

`openssl crl -verify` detects an invalid CRL issuer signature but still exits with status `0`. Scripts or callers that rely on the command exit status can therefore accept an invalidly signed CRL as verified.

## Provenance

Verified from supplied source, reproducer analysis, and patch. Initially identified by Swival Security Scanner: https://swival.dev

## Preconditions

Caller relies on `openssl crl -verify` exit status to decide whether a CRL signature is valid.

## Proof

In `crl_main()`, enabling `-verify` loads the issuer certificate and calls:

```c
i = X509_CRL_verify(x, pkey);
```

`X509_CRL_verify()` returns `0` for an invalid signature. The affected code handles that case by printing an error only:

```c
if (i == 0)
	BIO_printf(bio_err, "verify failure\n");
else
	BIO_printf(bio_err, "verify OK\n");
```

Because there is no `goto end` or nonzero return preservation, execution continues into normal output handling. With `-noout`, `ret = 0` is set. Without `-noout`, successful CRL serialization also sets `ret = 0`.

The command dispatcher returns the command handler return value as the process exit status, so an invalid CRL signature can produce a successful process exit.

## Why This Is A Real Bug

The command explicitly implements CRL signature verification. An invalid signature is a deterministic verification failure, and the code already recognizes it as `i == 0`. Reporting that failure only on stderr while returning success breaks the security decision for automation, policy checks, and scripts using `openssl crl -verify`.

This is not cosmetic output behavior: the process exit status is the machine-readable result commonly used by callers.

## Fix Requirement

When `X509_CRL_verify()` returns `0`, print `verify failure` and terminate the command through the existing error path so the default nonzero `ret` is returned.

## Patch Rationale

The patch preserves the existing success and internal-error behavior while making the explicit invalid-signature case fail closed.

`ret` is initialized to `1`, so adding `goto end` after `verify failure` causes the command to exit nonzero without requiring a new error code path. Resource cleanup remains centralized through the existing `end:` label.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/openssl/crl.c b/usr.bin/openssl/crl.c
index e64038d..441b21c 100644
--- a/usr.bin/openssl/crl.c
+++ b/usr.bin/openssl/crl.c
@@ -327,9 +327,10 @@ crl_main(int argc, char **argv)
 		EVP_PKEY_free(pkey);
 		if (i < 0)
 			goto end;
-		if (i == 0)
+		if (i == 0) {
 			BIO_printf(bio_err, "verify failure\n");
-		else
+			goto end;
+		} else
 			BIO_printf(bio_err, "verify OK\n");
 	}
```