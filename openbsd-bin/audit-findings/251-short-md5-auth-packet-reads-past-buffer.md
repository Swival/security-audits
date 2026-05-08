# short MD5-auth packet reads past buffer

## Classification

out-of-bounds read, medium severity. Confidence: certain.

## Affected Locations

`usr.sbin/ripd/auth.c:118`

## Summary

`auth_validate()` can read past the received RIP datagram when parsing cryptographic authentication. A packet with only the RIP header and `struct rip_auth` authentication marker is accepted far enough to enter the `AUTH_CRYPT` path, where `struct md5_auth` fields are read without first proving that the packet contains a complete `struct md5_auth`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The target interface is configured for cryptographic RIP authentication.
- A remote RIP sender can deliver a RIP response from UDP source port 520.
- The packet length is at least `RIP_HDR_LEN`, satisfying the receiver’s initial length gate.

## Proof

A minimal reproducing packet is 8 bytes total:

- RIP header.
- `struct rip_auth` with `auth_fixed = 0xffff`.
- `auth_type = htons(AUTH_CRYPT)`.
- No trailing `struct md5_auth`.

Reachability is confirmed because `recv_packet()` only requires `len >= RIP_HDR_LEN` before calling `auth_validate()` for responses at `usr.sbin/ripd/packet.c:155` and `usr.sbin/ripd/packet.c:195`.

Inside `auth_validate()`:

- The function advances past the RIP header and subtracts `RIP_HDR_LEN`.
- It accepts the 4-byte authentication header.
- It enters `AUTH_CRYPT`.
- It sets `a = (struct md5_auth *)(*buf + sizeof(*auth_head))`.
- It immediately reads `a->auth_keyid` for `md_list_find()` at `usr.sbin/ripd/auth.c:118`.

For the 8-byte packet, `a->auth_keyid` is read at packet offset 10, beyond the received datagram.

## Why This Is A Real Bug

The bounds check is missing before dereferencing `struct md5_auth`. Existing validation checks `auth_head->auth_fixed` and `auth_type`, but does not require `*len` to cover both `struct rip_auth` and `struct md5_auth` before reading `a->auth_keyid`, `a->auth_seq`, `a->auth_length`, and `a->auth_offset`.

This allows an unauthenticated remote sender to make `ripd` read stale or uninitialized bytes past the received packet before any MD5 validation occurs.

## Fix Requirement

Reject cryptographic-authentication packets unless the remaining length after the RIP header covers:

- `sizeof(struct rip_auth)`
- `sizeof(struct md5_auth)`

The rejection must occur before assigning or dereferencing the `struct md5_auth *`.

## Patch Rationale

The patch adds an early length check immediately after advancing past the RIP header and before `auth_head` and `md5_auth` parsing proceeds. For `AUTH_CRYPT`, `auth_validate()` now rejects packets shorter than `sizeof(struct rip_auth) + sizeof(struct md5_auth)`, preventing all subsequent reads of MD5 authentication fields from crossing the packet boundary.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ripd/auth.c b/usr.sbin/ripd/auth.c
index e48b880..0bda6e4 100644
--- a/usr.sbin/ripd/auth.c
+++ b/usr.sbin/ripd/auth.c
@@ -86,6 +86,13 @@ auth_validate(u_int8_t **buf, u_int16_t *len, struct iface *iface,
 	*buf += RIP_HDR_LEN;
 	*len -= RIP_HDR_LEN;
 
+	if (iface->auth_type == AUTH_CRYPT &&
+	    *len < sizeof(struct rip_auth) + sizeof(struct md5_auth)) {
+		log_debug("auth_validate: short authentication data, "
+		    "interface %s", iface->name);
+		return (-1);
+	}
+
 	auth_head = (struct rip_auth *)(*buf);
 
 	if (auth_head->auth_fixed != AUTH) {
```