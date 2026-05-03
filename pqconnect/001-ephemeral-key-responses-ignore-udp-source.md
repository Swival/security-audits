# Ephemeral Key Responses Ignore UDP Source

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

`src/pqconnect/pqcclient.py:558`

## Summary

`PQCClientConnectionHandler._request_ephemeral_keys()` accepted any UDP datagram that parsed as an `EphemeralKeyResponse`, without verifying that it came from the keyserver address the request was sent to.

A UDP-reachable attacker could race a forged ephemeral-key response, causing the client to derive tunnel keys from attacker-supplied ephemeral public keys. The client then installed a local `TunnelSession`, while the real server derived different secrets and could not complete the matching session, leaving the PQConnect tunnel unusable.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched.

## Preconditions

- The client is initiating a PQConnect handshake.
- The attacker can send UDP datagrams to the client socket.
- The forged `EphemeralKeyResponse` arrives before the legitimate keyserver response.

## Proof

`_request_ephemeral_keys()` sends an `EphemeralKeyRequest` to:

`(self._peer.get_external_ip(), self._peer.get_keyport())`

It then receives responses with:

```python
data, addr = self._transport.recvfrom(4096)
```

Before the patch, `addr` was assigned but never checked.

Any datagram that parsed through:

```python
KeyResponseHandler(data).response()
```

as an `EphemeralKeyResponse` was accepted. The handler then copied attacker-controlled public keys into:

```python
self._e_sntrup_r = resp.pqpk
self._e_x25519_r = resp.npqpk
```

and returned success.

`run()` subsequently called `initiate_handshake_0rtt()`, derived the 0-RTT handshake using those attacker-supplied ephemeral public keys, sent the initiation to the real peer, and installed the resulting client-side tunnel session through `set_tunnel()` and `add_peer()`.

The real server uses its own ephemeral private keys in the 0-RTT completion path. Because the client used attacker-supplied ephemeral public keys, the client and server derive different secrets, causing the server side to reject or fail the handshake while the client believes a tunnel exists.

## Why This Is A Real Bug

The UDP source address is security-relevant because the client explicitly targets a specific keyserver IP and port for ephemeral keys.

Ignoring the source allows an unauthenticated datagram from any reachable sender to influence the cryptographic material used for tunnel setup. The forged keys do not need to create a valid attacker-controlled tunnel; they only need to make the client and server derive different secrets. That is sufficient for attacker-triggered denial of service.

## Fix Requirement

Reject ephemeral-key responses unless the UDP source address exactly matches the expected keyserver IP and port:

```python
(self._peer.get_external_ip(), self._peer.get_keyport())
```

## Patch Rationale

The patch adds a source-address check immediately after `recvfrom()` and before parsing or accepting the response.

This ensures only datagrams from the keyserver endpoint requested by the client can be considered as candidate `EphemeralKeyResponse` packets. Forged packets from other UDP sources are ignored and cannot populate `_e_sntrup_r` or `_e_x25519_r`.

## Residual Risk

None

## Patch

```diff
diff --git a/src/pqconnect/pqcclient.py b/src/pqconnect/pqcclient.py
index c3ee5c5..c93f77e 100644
--- a/src/pqconnect/pqcclient.py
+++ b/src/pqconnect/pqcclient.py
@@ -541,6 +541,11 @@ class PQCClientConnectionHandler(Thread):
             while True:
                 try:
                     data, addr = self._transport.recvfrom(4096)
+                    if addr != (
+                        self._peer.get_external_ip(),
+                        self._peer.get_keyport(),
+                    ):
+                        continue
                     resp = KeyResponseHandler(data).response()
                     if not isinstance(resp, EphemeralKeyResponse):
                         continue
```