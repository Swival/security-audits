# ESP padding verifier checks only final pad byte

## Classification

security_control_failure, high severity, confidence: certain

## Affected Locations

`netinet/ip_esp.c:652`

## Summary

`esp_input` validates decrypted ESP padding by inspecting only the final padding byte before Pad Length and Next Protocol. ESP output emits self-describing padding bytes `1..padlen`, so the input path must verify every padding byte. With the original check, malformed ESP plaintext with a valid final pad byte is accepted, trimmed, and passed to `ipsec_common_input_cb`.

## Provenance

Verified from the provided source, reproduced behavior, and patch. Initially reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Caller supplies decrypted ESP plaintext with valid total length.
- ESP trailer has a Pad Length value within bounds.
- The final padding byte equals Pad Length when Pad Length is nonzero.
- Earlier padding bytes are malformed.

## Proof

`esp_output` creates self-describing padding:

- `netinet/ip_esp.c:863` writes padding bytes as `1, 2, ... padlen`.
- `netinet/ip_esp.c:868` stores Pad Length before Next Protocol.

`esp_input` originally validates only the last three decrypted bytes:

- `netinet/ip_esp.c:646` copies only final pad byte, Pad Length, and Next Protocol into `lastthree`.
- `netinet/ip_esp.c:649` bounds-checks Pad Length.
- `netinet/ip_esp.c:659` rejects only if final pad byte differs from Pad Length and Pad Length is nonzero.

Concrete malformed trailer:

```text
ff 02 02 04
```

For `padlen=2`, valid padding must be:

```text
01 02
```

But `lastthree` becomes:

```text
02 02 04
```

The original rejection condition is false because `lastthree[0] == lastthree[1]`. The packet is then trimmed at `netinet/ip_esp.c:668` and passed to `ipsec_common_input_cb` at `netinet/ip_esp.c:675`.

## Why This Is A Real Bug

The ESP output path establishes the padding invariant by writing deterministic self-describing padding bytes. The ESP input path is the corresponding verifier after decryption. Checking only the final pad byte fails to enforce that invariant and allows malformed decrypted ESP plaintext to pass as valid. This is a security control failure because malformed padding is accepted into the IPsec input path instead of being rejected.

## Fix Requirement

Verify every ESP padding byte. For Pad Length `N`, byte `i` of the padding must equal `i` for all `1 <= i <= N`. Reject the packet on the first mismatch and count it as bad encryption.

## Patch Rationale

The patch replaces the single final-byte comparison with a loop over all padding bytes:

- Iterates `plen` from `1` through `lastthree[1]`.
- Reads each padding byte from the mbuf with `m_copydata`.
- Compares each byte against its expected self-describing value.
- Preserves existing failure behavior: logs decryption failure, increments `esps_badenc`, and drops.

This directly aligns ESP input validation with ESP output padding generation.

## Residual Risk

None

## Patch

```diff
diff --git a/netinet/ip_esp.c b/netinet/ip_esp.c
index 2f508b6..d0cc831 100644
--- a/netinet/ip_esp.c
+++ b/netinet/ip_esp.c
@@ -656,13 +656,19 @@ esp_input(struct mbuf **mp, struct tdb *tdb, int skip, int protoff,
 		goto drop;
 	}
 
-	/* Verify correct decryption by checking the last padding bytes */
-	if ((lastthree[1] != lastthree[0]) && (lastthree[1] != 0)) {
-		DPRINTF("decryption failed for packet in SA %s/%08x",
-		    ipsp_address(&tdb->tdb_dst, buf, sizeof(buf)),
-		    ntohl(tdb->tdb_spi));
-		espstat_inc(esps_badenc);
-		goto drop;
+	/* Verify correct decryption by checking the padding bytes */
+	for (plen = 1; plen <= lastthree[1]; plen++) {
+		uint8_t pad;
+
+		m_copydata(m, m->m_pkthdr.len - lastthree[1] - 3 + plen,
+		    1, &pad);
+		if (pad != plen) {
+			DPRINTF("decryption failed for packet in SA %s/%08x",
+			    ipsp_address(&tdb->tdb_dst, buf, sizeof(buf)),
+			    ntohl(tdb->tdb_spi));
+			espstat_inc(esps_badenc);
+			goto drop;
+		}
 	}
 
 	/* Trim the mbuf chain to remove the padding */
```