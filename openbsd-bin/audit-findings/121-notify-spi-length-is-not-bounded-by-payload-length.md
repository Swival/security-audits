# NOTIFY SPI Length Is Not Bounded By Payload Length

## Classification

High severity out-of-bounds read.

## Affected Locations

`sbin/isakmpd/message.c:954`

## Summary

`message_validate_notify()` trusted the attacker-controlled NOTIFY `SPI_SZ` field before proving that the payload length contained that many SPI bytes. With an existing ISAKMP SA, a remote IKE peer could send a truncated NOTIFY payload declaring a cookie-sized SPI and trigger a 16-byte `memcmp()` read past the packet buffer.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A matching ISAKMP SA exists.
- The NOTIFY payload protocol is `ISAKMP`.
- The NOTIFY payload declares `SPI_SZ == ISAKMP_HDR_COOKIES_LEN`.
- The NOTIFY payload length is shorter than `ISAKMP_NOTIFY_SPI_OFF + SPI_SZ`.

## Proof

`message_recv()` accepts packets whose NOTIFY payload length satisfies only the generated fixed minimum size. That minimum excludes the variable-length SPI field.

The vulnerable path is:

- `message_parse_payloads()` checks `len >= message_payload_sz(payload)`.
- For `ISAKMP_PAYLOAD_NOTIFY`, `message_payload_sz()` returns `ISAKMP_NOTIFY_SZ`.
- `ISAKMP_NOTIFY_SZ` covers the fixed NOTIFY fields but not the variable SPI bytes.
- `message_recv()` sets `msg->isakmp_sa` from header cookies before payload validation when an SA exists.
- `message_validate_payloads()` calls `message_validate_notify()`.
- `message_validate_notify()` reaches SPI validation when `proto == ISAKMP`, `SPI_SZ == ISAKMP_HDR_COOKIES_LEN`, and `msg->isakmp_sa != NULL`.
- The original code then executes:

```c
memcmp(p->p + ISAKMP_NOTIFY_SPI_OFF, msg->isakmp_sa->cookies,
    ISAKMP_HDR_COOKIES_LEN)
```

For a header-length-40 packet, `p->p + ISAKMP_NOTIFY_SPI_OFF` is exactly one byte past the allocated packet buffer, so the `memcmp()` reads past the packet before any later rejection.

## Why This Is A Real Bug

The generic payload-length validation only proves that the fixed NOTIFY header is present. It does not prove that the variable SPI field exists. `SPI_SZ` is read from the packet and can request 16 bytes, but the code immediately uses that value to decide whether to read 16 bytes from `p->p + ISAKMP_NOTIFY_SPI_OFF`.

Because the read occurs during validation, before later cleartext phase-2 rejection, a remote peer with valid ISAKMP cookies can trigger the out-of-bounds read through normal packet processing.

## Fix Requirement

Before any SPI validation or `memcmp()`, require:

```c
GET_ISAKMP_GEN_LENGTH(p->p) >= ISAKMP_NOTIFY_SPI_OFF + GET_ISAKMP_NOTIFY_SPI_SZ(p->p)
```

Reject malformed packets that fail this bound.

## Patch Rationale

The patch adds an explicit length check in `message_validate_notify()` after DOI/protocol validation and before SPI comparison:

```c
if (GET_ISAKMP_GEN_LENGTH(p->p) < ISAKMP_NOTIFY_SPI_OFF +
    GET_ISAKMP_NOTIFY_SPI_SZ(p->p)) {
	log_print("message_validate_notify: payload too short");
	message_drop(msg, ISAKMP_NOTIFY_PAYLOAD_MALFORMED, 0, 1, 1);
	return -1;
}
```

This validates the full fixed-plus-variable NOTIFY SPI extent using the payload's own generic length. If the declared SPI does not fit inside the payload, processing stops with `ISAKMP_NOTIFY_PAYLOAD_MALFORMED`, preventing the out-of-bounds `memcmp()`.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/isakmpd/message.c b/sbin/isakmpd/message.c
index ee0df3a..5e6959f 100644
--- a/sbin/isakmpd/message.c
+++ b/sbin/isakmpd/message.c
@@ -911,6 +911,12 @@ message_validate_notify(struct message *msg, struct payload *p)
 		message_free(msg);
 		return -1;
 	}
+	if (GET_ISAKMP_GEN_LENGTH(p->p) < ISAKMP_NOTIFY_SPI_OFF +
+	    GET_ISAKMP_NOTIFY_SPI_SZ(p->p)) {
+		log_print("message_validate_notify: payload too short");
+		message_drop(msg, ISAKMP_NOTIFY_PAYLOAD_MALFORMED, 0, 1, 1);
+		return -1;
+	}
 
 	/* Validate the SPI. XXX Just ISAKMP for now.  */
 	if (proto == ISAKMP_PROTO_ISAKMP &&
```