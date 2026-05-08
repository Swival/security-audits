# Short AC-Cookie Triggers Out-of-Bounds Read

## Classification

Out-of-bounds read, medium severity. Confidence: certain.

## Affected Locations

`usr.sbin/npppd/pppoe/pppoe_session.c:375`

## Summary

`pppoe_session_recv_PADR()` accepts an attacker-supplied PPPoE PADR `AC_COOKIE` tag of any length, then unconditionally reads four bytes from `ac_cookie->value`. If the tag is shorter than four bytes, session setup performs an out-of-bounds read from the TLV parser arena or adjacent stack memory.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `npppd` processes a PADR from a remote PPPoE peer on the local Ethernet segment.
- The PADR contains an `AC_COOKIE` TLV.
- The `AC_COOKIE` TLV length is 0, 1, 2, or 3 bytes.

## Proof

`pppoed_recv_PADR()` parses the attacker-controlled PADR and passes the resulting `tag_list` to `pppoe_session_recv_PADR()`.

Inside `pppoe_session_recv_PADR()`:

- The tag scan records any `PPPOE_TAG_AC_COOKIE` in `ac_cookie`.
- If `ac_cookie` is present, the code uses `ac_cookie->value` as a hash key.
- It then executes:

```c
_this->acookie = *(uint32_t *)(ac_cookie->value);
```

No preceding check proves `ac_cookie->length >= sizeof(uint32_t)`.

A PADR containing an `AC_COOKIE` TLV of length 1, 2, or 3 passes parsing and causes the four-byte load to read beyond the tag value. A zero-length final `AC_COOKIE` can also make the four-byte load start at the end of the TLV arena.

The reproducer confirmed this with an ASan harness matching the parser arena layout, producing a four-byte stack-buffer-overflow read when the cookie value begins at the end of `tlvspace`.

## Why This Is A Real Bug

The vulnerable read is reachable from attacker-controlled L2 PPPoE input during normal PADR handling. The TLV parser preserves the attacker-supplied `AC_COOKIE` length, but the session code treats the value as a fixed-width `uint32_t` without validating that the TLV contains four bytes. Therefore malformed but parseable PADR input can make the daemon read memory beyond the supplied tag value during session setup.

## Fix Requirement

Reject `AC_COOKIE` tags unless their length is exactly `sizeof(uint32_t)`.

## Patch Rationale

The patch adds a length check immediately before any fixed-width cookie use:

```c
if (ac_cookie->length != sizeof(uint32_t))
	goto fail;
```

This ensures the later four-byte load is only performed when the TLV value contains exactly four bytes. Requiring exact length also prevents ambiguous cookies with trailing bytes from being accepted.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/npppd/pppoe/pppoe_session.c b/usr.sbin/npppd/pppoe/pppoe_session.c
index 104c3a7..cd24afa 100644
--- a/usr.sbin/npppd/pppoe/pppoe_session.c
+++ b/usr.sbin/npppd/pppoe/pppoe_session.c
@@ -377,6 +377,9 @@ pppoe_session_recv_PADR(pppoe_session *_this, slist *tag_list)
 	}
 
 	if (ac_cookie) {
+		if (ac_cookie->length != sizeof(uint32_t))
+			goto fail;
+
 		/* avoid a session which has already has cookie. */
 		if (hash_lookup(pppoed0->acookie_hash,
 		    (void *)ac_cookie->value) != NULL)
```