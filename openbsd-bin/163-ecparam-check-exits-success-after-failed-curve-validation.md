# ecparam check exits success after failed curve validation

## Classification

security_control_failure, high severity, confidence certain

## Affected Locations

`usr.bin/openssl/ecparam.c:386`

## Summary

`openssl ecparam -check` treats `EC_GROUP_check()` as the elliptic-curve parameter validation decision, but the failure branch only reports `failed` and continues. With `-noout`, no later output operation fails, so control reaches `ret = 0` and the command exits successfully despite rejected EC parameters.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

caller trusts `ecparam -check` exit status for supplied parameter files

## Proof

- `ecparam_main()` loads supplied EC parameters through `PEM_read_bio_ECPKParameters()` or `d2i_ECPKParameters_bio()`.
- When `-check` is set, validation is performed by `EC_GROUP_check(group, NULL)` at `usr.bin/openssl/ecparam.c:386`.
- On validation failure, the old code prints `failed` and OpenSSL errors, but does not set `ret`, does not jump to cleanup, and does not otherwise preserve failure.
- With `-noout`, the output-write block is skipped, and when `-genkey` is unset execution reaches `ret = 0`.
- The top-level dispatcher returns the subcommand status directly via `fp->func(argc, argv)`, so this becomes process exit success.
- A practical invalid-but-parseable trigger exists: explicit P-256 parameters with the group order integer mutated can parse into an `EC_GROUP` while failing `EC_GROUP_check()`.

## Why This Is A Real Bug

The command explicitly offers `-check` to validate EC parameters. A caller reasonably using `openssl ecparam -check -noout -in bad.pem` as a gate receives a zero exit status even when the validator rejects the parameters. This is a fail-open security-control bug: automation can accept attacker-supplied invalid curve parameters after the checker reports failure only on stderr.

## Fix Requirement

On `EC_GROUP_check()` failure, `ecparam_main()` must return nonzero. This can be done by jumping to the existing cleanup path before `ret = 0` is assigned, or by explicitly setting a nonzero status before continuing.

## Patch Rationale

The patch adds `goto end;` in the `EC_GROUP_check()` failure branch. `ret` is initialized to `1`, so jumping to `end` preserves failure while reusing existing cleanup for `BIO` and `EC_GROUP` objects. Successful validation still prints `ok` and continues through the existing output and key-generation paths.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/openssl/ecparam.c b/usr.bin/openssl/ecparam.c
index 285f5d5..9887fbf 100644
--- a/usr.bin/openssl/ecparam.c
+++ b/usr.bin/openssl/ecparam.c
@@ -386,6 +386,7 @@ ecparam_main(int argc, char **argv)
 		if (!EC_GROUP_check(group, NULL)) {
 			BIO_printf(bio_err, "failed\n");
 			ERR_print_errors(bio_err);
+			goto end;
 		} else
 			BIO_printf(bio_err, "ok\n");
```
