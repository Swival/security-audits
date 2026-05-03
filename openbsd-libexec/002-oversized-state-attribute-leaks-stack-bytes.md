# oversized State attribute leaks stack bytes

## Classification

Information disclosure, medium severity.

Confidence: certain.

## Affected Locations

`login_radius/raddauth.c:631`

## Summary

`parse_challenge()` trusted the RADIUS attribute length byte before confirming that the attribute fit inside the authenticated packet length. A malicious configured RADIUS backend could send an authenticated `Access-Challenge` with an oversized `PW_STATE` length, causing `memcpy()` to read past the received datagram into the stack local `auth` buffer in `rad_recv()`. The copied bytes were then returned to the backend in the next `Access-Request` as a `PW_STATE` attribute.

## Provenance

Found by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied source and reproducer evidence.

## Preconditions

- The attacker controls or compromises a configured RADIUS backend.
- The backend knows the shared secret.
- The backend sends a response with a valid RADIUS response authenticator.
- The client enters the interactive challenge path that sends the received `State` back in a later request.

## Proof

A concrete reproduced trigger is a 22-byte `Access-Challenge` response:

- RADIUS header length is valid for the received datagram.
- The packet contains a `PW_STATE` attribute type followed by an attribute length byte of `255`.
- The response authenticator is valid over `auth.length` bytes and the shared secret.

Execution then proceeds as follows:

- `rad_recv()` accepts the packet after checking `auth.length <= total_length`, source IP, and the MD5 response authenticator.
- `parse_challenge()` starts with `length == 2`.
- It reads `attribute_len == 255`.
- It subtracts `255` from `length`, then converts `attribute_len` to payload length `253`.
- At `login_radius/raddauth.c:636`, it copies 253 bytes from `auth.data + 2` into `state`.
- Those bytes were not received in the UDP datagram and were not covered by the authenticator.
- In the challenge loop, `raddauth()` passes that `state` to `rad_request()`.
- `rad_request()` emits the leaked bytes as a `PW_STATE` attribute at `login_radius/raddauth.c:435`.

The leak is truncated at the first NUL byte because `rad_request()` uses `strlen(state)`, but the oversized attribute still creates a practical stack-memory disclosure path back to the backend.

## Why This Is A Real Bug

The packet authenticator only proves integrity for the declared packet bytes. It does not make bytes beyond the received attribute payload valid. `parse_challenge()` failed to enforce the RADIUS attribute invariant that each attribute must be at least two bytes long and must not exceed the remaining packet bytes.

Because `auth` is a stack local in `rad_recv()` and `recvfrom()` does not initialize bytes beyond the received datagram, the oversized `PW_STATE` copy can read stale stack contents. The copied data is then observable by the malicious backend in the next request.

## Fix Requirement

Reject malformed challenge attributes before consuming them:

- Reject if fewer than 2 bytes remain for an attribute header.
- Reject if `attribute_len < 2`.
- Reject if `attribute_len > length`.

## Patch Rationale

The patch validates each attribute before subtracting its length or copying its payload. This preserves normal parsing for well-formed attributes and aborts malformed authenticated responses with the existing `"bogus auth packet from server"` error path.

The key correction is that `attribute_len` is checked against the current remaining packet length while it still includes the two-byte attribute header.

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