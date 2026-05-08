# short simple-auth packet reads past buffer

## Classification

out-of-bounds read; medium severity; confidence certain.

## Affected Locations

`usr.sbin/ripd/auth.c:107`

## Summary

`auth_validate()` accepts a RIP packet that has only enough bytes for the RIP header and the simple-auth type fields, then copies a full simple-auth password from the remaining packet without verifying that a complete authentication entry is present. A remote RIP sender can therefore cause authentication to read past the received packet boundary when the receiving interface uses `AUTH_SIMPLE`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

The receiving interface is configured with `AUTH_SIMPLE`.

## Proof

`recv_packet` permits a RIP response from source port 520 to reach `auth_validate()` after checking only that the packet length is at least `RIP_HDR_LEN`.

Inside `auth_validate()`:

- The function advances `*buf` by `RIP_HDR_LEN` and subtracts `RIP_HDR_LEN` from `*len`.
- It treats the remaining bytes as `struct rip_auth` without first requiring a full RIP authentication entry.
- If `auth_fixed == AUTH` and `auth_type == AUTH_SIMPLE`, execution reaches the simple-auth branch.
- The simple-auth branch executes:

```c
bcopy(*buf+sizeof(*auth_head), pwd, MAX_SIMPLE_AUTH_LEN);
```

A packet of 8 bytes total can contain the RIP header plus `auth_fixed = 0xffff` and `auth_type = AUTH_SIMPLE`. At that point, the packet has no password bytes remaining, but the copy reads bytes 8 through 23 from the receive buffer.

## Why This Is A Real Bug

The vulnerable read is before password comparison and is driven entirely by packet length and authentication fields controlled by a remote RIP sender. The code assumes that `RIP_ENTRY_LEN` bytes remain after the RIP header, but no such check exists on the `AUTH_SIMPLE` path. This makes the authentication comparison consume bytes that were not part of the received packet.

The receive allocation may be larger than the packet, so the most direct impact is a stale or unreceived receive-buffer read rather than a guaranteed guard-page crash. It is still an out-of-bounds read relative to the packet data and can influence authentication behavior using memory outside the packet.

## Fix Requirement

Reject simple-auth packets unless at least one full RIP authentication entry remains before copying the password.

## Patch Rationale

The patch adds a length check in the `AUTH_SIMPLE` branch:

```c
if (*len < RIP_ENTRY_LEN)
	return (-1);
```

`RIP_ENTRY_LEN` is the required size of the authentication entry containing `struct rip_auth` plus the simple password bytes. Checking it immediately before the password copy prevents `bcopy()` from reading beyond the received packet while preserving the existing authentication flow for well-formed packets.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ripd/auth.c b/usr.sbin/ripd/auth.c
index e48b880..2e6cd21 100644
--- a/usr.sbin/ripd/auth.c
+++ b/usr.sbin/ripd/auth.c
@@ -105,6 +105,8 @@ auth_validate(u_int8_t **buf, u_int16_t *len, struct iface *iface,
 
 	switch (iface->auth_type) {
 	case AUTH_SIMPLE:
+		if (*len < RIP_ENTRY_LEN)
+			return (-1);
 		bcopy(*buf+sizeof(*auth_head), pwd, MAX_SIMPLE_AUTH_LEN);
 		if (bcmp(pwd, iface->auth_key, MAX_SIMPLE_AUTH_LEN)) {
 			log_debug("auth_validate: wrong password, "
```