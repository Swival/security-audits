# Short RIP Packet Reads Past Authentication Header

## Classification

Out-of-bounds read, medium severity.

## Affected Locations

`usr.sbin/ripd/auth.c:90`

## Summary

`auth_validate()` accepts a packet length that only needs to cover the RIP header before it advances past that header and dereferences the authentication entry. A RIP packet with no complete authentication entry can therefore cause reads past the received datagram before authentication rejection occurs.

## Provenance

Verified from the supplied source, reproducer summary, and patch.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `ripd` receives an attacker-controlled short RIP packet on an interface.
- The packet reaches `auth_validate()` after earlier RIP packet parsing.
- The UDP payload is at least `RIP_HDR_LEN` but shorter than `RIP_HDR_LEN + RIP_ENTRY_LEN`.

## Proof

The receive path accepts packets with length at least `RIP_HDR_LEN` and checks the RIP version before calling `auth_validate()`.

Inside `auth_validate()`:

- `*buf += RIP_HDR_LEN` advances the buffer past the RIP header.
- `*len -= RIP_HDR_LEN` reduces the remaining length.
- `auth_head = (struct rip_auth *)(*buf)` casts the remaining buffer to an authentication header.
- `auth_head->auth_fixed` and `auth_head->auth_type` are read before proving that the remaining buffer contains `sizeof(struct rip_auth)` or a full RIP authentication entry.

For a RIP response whose UDP payload is exactly 4 or 5 bytes, the remaining length after the RIP header is 0 or 1 byte. The subsequent `auth_head` dereference reads beyond the valid datagram contents.

## Why This Is A Real Bug

The dereference is reachable before any size check covering the authentication entry. The attacker controls the UDP payload length, and the earlier packet path only guarantees the RIP header is present. Therefore a remote RIP sender can trigger a pre-rejection out-of-bounds read during authentication parsing.

The daemon’s receive allocation may be larger than the datagram, so the read will typically consume stale or uninitialized receive-buffer bytes rather than immediately faulting. That does not remove the out-of-bounds read: the parser still reads bytes outside the packet’s valid length.

## Fix Requirement

Reject packets unless the length covers both:

- the RIP header; and
- a full authentication/RIP entry before `auth_head` is dereferenced.

## Patch Rationale

The patch adds an early length check before advancing `*buf`:

```c
if (*len < RIP_HDR_LEN + RIP_ENTRY_LEN) {
	log_debug("auth_validate: bad packet size, interface %s",
	    iface->name);
	return (-1);
}
```

This ensures the packet contains the RIP header plus a complete first RIP entry, which is the unit used for the authentication header. Only after that validation does the function advance past the RIP header and inspect `struct rip_auth`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ripd/auth.c b/usr.sbin/ripd/auth.c
index e48b880..0b0830e 100644
--- a/usr.sbin/ripd/auth.c
+++ b/usr.sbin/ripd/auth.c
@@ -83,6 +83,12 @@ auth_validate(u_int8_t **buf, u_int16_t *len, struct iface *iface,
 	u_int8_t		*auth_data;
 	u_int8_t		*b = *buf;
 
+	if (*len < RIP_HDR_LEN + RIP_ENTRY_LEN) {
+		log_debug("auth_validate: bad packet size, interface %s",
+		    iface->name);
+		return (-1);
+	}
+
 	*buf += RIP_HDR_LEN;
 	*len -= RIP_HDR_LEN;
```