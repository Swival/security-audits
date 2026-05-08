# Missing Service Tag Logs Uninitialized Stack Bytes

## Classification

Information disclosure, medium severity. Confidence: certain.

## Affected Locations

`usr.sbin/npppd/pppoe/pppoed.c:899`

## Summary

`pppoed_recv_PADI` logs the local stack buffer `sn` with `%s` when denying a PADI request without an accepted service name. If the attacker omits all `SERVICE_NAME` tags, `sn` is never initialized before that log call, so daemon logs can contain uninitialized stack bytes.

## Provenance

Verified from the supplied source and reproducer evidence. Originally identified by Swival Security Scanner: https://swival.dev

## Preconditions

- `pppoed` receives an attacker-controlled PADI frame.
- The attacker can read `pppoed` daemon logs.
- The PADI frame omits every `SERVICE_NAME` tag.

## Proof

- `pppoed_input` parses PPPoE discovery tags and dispatches valid PADI packets to `pppoed_recv_PADI`.
- In `pppoed_recv_PADI`, `sn` is declared as a stack buffer at `usr.sbin/npppd/pppoe/pppoed.c:862`.
- `sn` is only populated in the `PPPOE_TAG_SERVICE_NAME` branch at `usr.sbin/npppd/pppoe/pppoed.c:885`.
- If no `SERVICE_NAME` tag exists, `tlv_service_name` remains `NULL`.
- The denial path logs `service-name=%s` using `sn` at `usr.sbin/npppd/pppoe/pppoed.c:899`.
- `pppoed_log` forwards the format string to `vlog_printf`, which writes through daemon logging sinks, making the uninitialized read observable in logs.

## Why This Is A Real Bug

A valid PADI can contain zero tags or only non-`SERVICE_NAME` tags. That path reaches the denial log with `tlv_service_name == NULL` while `sn` still contains indeterminate stack data. Formatting it with `%s` reads until a NUL byte and emits those bytes to logs, creating a concrete information disclosure under the stated log-read precondition.

## Fix Requirement

Initialize `sn` to an empty C string before scanning tags so all later `%s` log uses are defined even when no `SERVICE_NAME` tag is present.

## Patch Rationale

The patch sets `sn[0] = '\0';` immediately after initializing `tlv_hostuniq` and `tlv_service_name`. This preserves existing behavior when a service-name tag is present, while making the missing-tag denial path log an empty service name instead of stack contents.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/npppd/pppoe/pppoed.c b/usr.sbin/npppd/pppoe/pppoed.c
index e8d2242..2742d1f 100644
--- a/usr.sbin/npppd/pppoe/pppoed.c
+++ b/usr.sbin/npppd/pppoe/pppoed.c
@@ -873,6 +873,7 @@ pppoed_recv_PADI(pppoed_listener *_this, uint8_t shost[ETHER_ADDR_LEN],
 
 	tlv_hostuniq = NULL;
 	tlv_service_name = NULL;
+	sn[0] = '\0';
 
 	service_name = "";
 	if (_this->conf->service_name != NULL)
```