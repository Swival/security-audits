# MS-CHAP chap length drives username overread

## Classification

High severity out-of-bounds read.

Confidence: certain.

## Affected Locations

`usr.sbin/radiusd/radiusd_eap2mschap.c:488`

## Summary

A remote EAP supplicant can send an EAP-MS-CHAPV2 Response whose outer EAP length is small but whose inner CHAP length is oversized. `eap_recv_mschap()` derives the username length from the attacker-controlled CHAP length and passes it to `strndup()`, causing the process to read past the received EAP buffer.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

- The attacker is a remote EAP supplicant communicating through the NAS/RADIUS client.
- The supplicant has a valid `State` from a prior EAP-Identity challenge.
- The stored request is in `EAP_CHAP_CHALLENGE_SENT` state.

## Proof

`eap_recv()` concatenates EAP-Message attributes into a 512-byte stack buffer, validates only that `ntohs(eap->length) <= msgsiz`, finds the attacker-provided `State` in the `eapt` tree, and passes the received EAP-MS-CHAPV2 buffer to `eap_recv_mschap()`.

In `eap_recv_mschap()`:

- `eapsiz` is decoded from `ntohs(chap->eap.length)`.
- The CHAP Response size check incorrectly uses `htons(resp->chap.length)` for the minimum-length comparison.
- The code does not verify that `ntohs(resp->chap.length)` fits inside the validated EAP length.
- `namelen` is computed from `ntohs(resp->chap.length)`.
- `strndup(resp->chap_name, namelen)` then reads `namelen` bytes from the username field.

Concrete reproduced malformed input:

- `eap.length = 59`
- `chap.length = 0xffff`
- concatenated EAP-Message buffer size = 512 bytes
- bytes at offsets `59..511` are non-NUL

This makes `namelen = 65481`. Since the received stack buffer contains only 512 bytes, `strndup()` reads past the buffer after the 453 controlled trailing bytes.

## Why This Is A Real Bug

The outer EAP length validation only proves that the EAP packet fits in the received EAP-Message buffer. It does not prove that the nested CHAP payload length fits within the EAP packet.

The vulnerable path uses the nested CHAP length as authoritative for username copying. Because the attacker controls `chap.length`, and because the code fails to bound it by `eap.length`, the username copy can extend beyond the received packet. This is a concrete out-of-bounds read reachable remotely after normal EAP state establishment.

## Fix Requirement

Decode `chap.length` with `ntohs()` and reject any CHAP Response where the decoded CHAP length is either:

- smaller than the required MS-CHAP Response payload size, or
- larger than the available CHAP bytes inside the validated EAP packet.

## Patch Rationale

The patch corrects the byte-order conversion and adds the missing containment check:

```diff
-		    htons(resp->chap.length) <
+		    ntohs(resp->chap.length) <
 		    sizeof(struct eap_mschap_response) -
+		    offsetof(struct eap_mschap_response, chap) ||
+		    ntohs(resp->chap.length) > eapsiz -
 		    offsetof(struct eap_mschap_response, chap)) {
```

This ensures `chap.length` is interpreted from network byte order to host byte order before comparison, and ensures the inner CHAP payload cannot claim more bytes than are present inside the already-validated EAP packet. As a result, the later `namelen` calculation remains bounded by the received EAP buffer.

## Residual Risk

None

## Patch

`216-ms-chap-chap-length-drives-username-overread.patch` applies to `usr.sbin/radiusd/radiusd_eap2mschap.c` and fixes the vulnerable CHAP Response length validation in `eap_recv_mschap()`.