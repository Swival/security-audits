# Malformed Challenge Attribute Causes Backwards Parser Walk

## Classification

Denial of service, high severity.

Confidence: certain.

## Affected Locations

`login_radius/raddauth.c:620`

## Summary

`parse_challenge()` trusted the RADIUS attribute length byte before validating that it included the required two-byte attribute header and fit inside the remaining Access-Challenge payload. A malicious configured RADIUS server that knows the shared secret could send an authenticated Access-Challenge with an attribute length of `0` or `1`, causing the parser to walk backward, loop indefinitely, or pass a negative length to `memcpy()`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The attacker controls the configured RADIUS server.
- The attacker knows the shared secret.
- The attacker can return a response that passes `rad_recv()` source-address and response-authenticator verification.
- A login authentication attempt reaches Access-Challenge handling.

## Proof

`rad_recv()` verifies the response source address and shared-secret response authenticator, then calls `parse_challenge()` for `PW_ACCESS_CHALLENGE`.

In `parse_challenge()`:

```c
attribute = *ptr++;
attribute_len = *ptr++;
length -= attribute_len;
attribute_len -= 2;
```

Before the patch, there was no check that the raw `attribute_len` was at least `2` or less than or equal to the remaining packet length.

Reproduced behavior:

- For an unknown attribute with raw length `0`, `length` is not reduced and `attribute_len` becomes `-2`; `ptr += attribute_len` walks backward to the same attribute, causing an infinite loop.
- This happens after `alarm(0)` in `rad_recv()`, so the receive timeout has already been canceled.
- For `PW_STATE` with raw length `0` or `1`, `memcpy(state, ptr, attribute_len)` receives a negative `int` converted to a huge `size_t`, causing memory corruption or a crash.
- For `PW_PORT_MESSAGE`, the same malformed length can reach challenge copying or output paths with invalid bounds.

## Why This Is A Real Bug

RADIUS attributes encode length as the total attribute size, including the one-byte type and one-byte length fields. Therefore, valid attribute lengths must be at least `2`.

The old parser subtracted `2` from an unchecked attacker-controlled byte. Values below `2` produced negative payload lengths, which were then used for pointer advancement and `memcpy()` sizing. Because the malicious response can be authenticated by a configured backend with the shared secret, the packet is accepted as legitimate before parsing.

The impact is attacker-controlled denial of service against the login authentication helper through either a hang or crash.

## Fix Requirement

Reject malformed challenge attributes when:

- Fewer than two bytes remain for the attribute header.
- The raw attribute length is less than `2`.
- The raw attribute length exceeds the remaining packet data.

## Patch Rationale

The patch validates the remaining packet length before reading an attribute header and validates the raw attribute length before subtracting the two-byte header size.

This preserves normal parsing for valid attributes while rejecting malformed Access-Challenge payloads with the same existing fatal error style used for bogus authentication packets.

## Residual Risk

None

## Patch

```diff
diff --git a/login_radius/raddauth.c b/login_radius/raddauth.c
index 6625203..8d17ccd 100644
--- a/login_radius/raddauth.c
+++ b/login_radius/raddauth.c
@@ -619,8 +619,12 @@ parse_challenge(auth_hdr_t *authhdr, char *state, char *challenge)
 	*state = 0;
 
 	while (length > 0) {
+		if (length < 2)
+			errx(1, "bogus auth packet from server");
 		attribute = *ptr++;
 		attribute_len = *ptr++;
+		if (attribute_len < 2 || attribute_len > length)
+			errx(1, "bogus auth packet from server");
 		length -= attribute_len;
 		attribute_len -= 2;
 
```