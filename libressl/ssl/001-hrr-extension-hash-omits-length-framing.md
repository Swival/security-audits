# HRR extension hash omits length framing

## Classification

security_control_failure, high severity, confidence: certain

## Affected Locations

`ssl_tlsext.c:1948`

## Summary

The TLS 1.3 server-side HelloRetryRequest ClientHello consistency hash includes known extension type values and most extension payload bytes, but omits each extension length field. This makes the hash non-injective over encoded extension framing: two ClientHellos can produce identical hash input while parsing to different extension payloads.

After HRR, `tlsext_supportedgroups_server_process()` relies on that hash to ensure `supported_groups` did not change, without independently comparing the saved group list. A malicious TLS 1.3 client can shift bytes across extension length boundaries and make a modified second ClientHello pass the HRR consistency check.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Server negotiates TLS 1.3.
- Server sends HelloRetryRequest.
- Malicious client controls both ClientHello messages.
- The affected server path uses `tlsext_clienthello_hash_extension()` for HRR ClientHello consistency.

## Proof

`tlsext_parse()` hashes each known ClientHello extension on the TLS 1.3 server path by calling `tlsext_clienthello_hash_extension()`.

Before the patch, `tlsext_clienthello_hash_extension()` updated the HRR hash with:

- the extension type
- raw extension data for most extensions
- no extension length field

A concrete framing collision exists on a little-endian host:

- First ClientHello:
  - `session_ticket` data: `0a 00 00 06`
  - `supported_groups` data: `00 02 00 1d`
- Second ClientHello:
  - `session_ticket` data: empty
  - `supported_groups` data: `00 06 0a 00 00 02 00 1d`

Because the length fields are omitted, the concatenated hash stream is identical. The parsed `supported_groups` value changes from:

```text
[0x001d]
```

to:

```text
[0x0a00, 0x0002, 0x001d]
```

`tlsext_supportedgroups_server_process()` accepts the second form after basic length checks on the HRR path and relies on the ClientHello extension hash for immutability. `key_share` data is intentionally excluded from the consistency hash so the client can add the requested HRR share.

## Why This Is A Real Bug

TLS 1.3 HRR requires the second ClientHello to be consistent with the first, except for explicitly permitted changes. The implementation enforces that property through a hash of ClientHello extensions.

A hash used as a framing-sensitive consistency control must bind the encoded structure, not only a lossy concatenation of selected fields. Omitting the extension length field allows distinct extension encodings to collide in the HRR consistency hash while producing different parsed extension semantics.

The reproduced collision shows a practical way to modify `supported_groups` after HRR while satisfying the existing hash check. That is a failure of the intended security control, not only a theoretical parser ambiguity.

## Fix Requirement

Include each hashed extension's length field in the TLS 1.3 HRR ClientHello consistency hash before hashing extension payload bytes.

## Patch Rationale

The patch records `CBS_len(cbs)` as the extension length and feeds it into `tls13_clienthello_hash_update_bytes()` before hashing the extension data.

This binds the hash to the extension framing:

```diff
+	uint16_t len = CBS_len(cbs);
...
+	if (!tls13_clienthello_hash_update_bytes(ctx, (void *)&len, sizeof(len)))
+		return 0;
```

The existing exclusions for `early_data`, `cookie`, `padding`, `pre_shared_key`, and `key_share` are preserved, so the fix does not change the intended TLS 1.3 HRR exceptions. It only prevents collisions between different length-framed encodings for extensions that are meant to be stable across HRR.

## Residual Risk

None

## Patch

`001-hrr-extension-hash-omits-length-framing.patch`

```diff
diff --git a/ssl_tlsext.c b/ssl_tlsext.c
index d879b33..367cd75 100644
--- a/ssl_tlsext.c
+++ b/ssl_tlsext.c
@@ -2558,6 +2558,7 @@ tlsext_clienthello_hash_extension(SSL *s, uint16_t type, CBS *cbs)
 	 * cookie may be added, padding may be removed.
 	 */
 	struct tls13_ctx *ctx = s->tls13;
+	uint16_t len = CBS_len(cbs);
 
 	if (type == TLSEXT_TYPE_early_data || type == TLSEXT_TYPE_cookie ||
 	    type == TLSEXT_TYPE_padding)
@@ -2571,6 +2572,8 @@ tlsext_clienthello_hash_extension(SSL *s, uint16_t type, CBS *cbs)
 	 */
 	if (type == TLSEXT_TYPE_pre_shared_key || type == TLSEXT_TYPE_key_share)
 		return 1;
+	if (!tls13_clienthello_hash_update_bytes(ctx, (void *)&len, sizeof(len)))
+		return 0;
 	if (!tls13_clienthello_hash_update(ctx, cbs))
 		return 0;
```