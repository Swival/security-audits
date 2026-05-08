# Duplicate Classless Route Requests Overflow Priority List

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`usr.sbin/dhcpd/options.c:237`

## Summary

`create_priority_list()` gave RFC 3442 classless route option codes priority by appending them from the DHCP Parameter Request List before the normal deduplication pass. That special pass did not check whether the option code had already been stored. A remote DHCP client could send many duplicate classless route requests and make `priority_len` exceed the 256-byte `priority_list` stack buffer allocated by `cons_options()`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced with the committed logic and patched in `262-duplicate-classless-route-requests-overflow-priority-list.patch`.

## Preconditions

- The server calls `cons_options()` with an attacker-controlled DHCP Parameter Request List.
- A remote DHCP client is on a served network.
- The request list contains many duplicate `DHO_CLASSLESS_STATIC_ROUTES` or `DHO_CLASSLESS_MS_STATIC_ROUTES` option codes.

## Proof

`do_packet()` parses client-controlled options into `tp.options`.

`dhcp_reply()` passes the parsed request data to `cons_options()`.

`cons_options()` allocates:

```c
unsigned char priority_list[256];
```

and passes it to `create_priority_list()`.

In the vulnerable logic, `create_priority_list()` appends every duplicate classless route byte during the special priority pass:

```c
if (prl[i] == DHO_CLASSLESS_STATIC_ROUTES ||
    prl[i] == DHO_CLASSLESS_MS_STATIC_ROUTES) {
        priority_list[priority_len++] = prl[i];
        stored_list[prl[i]] = 1;
}
```

The deduplication check only happens later, after the duplicates have already incremented `priority_len`.

A parameter request list of length 253 filled with option code `121` is sufficient. After four mandatory entries, the 253rd duplicate writes `priority_list[256]`. The subsequent default-list pass can continue writing past the stack buffer.

An ASan harness using the committed logic reports a stack-buffer-overflow on the `priority_list` write.

## Why This Is A Real Bug

The input is attacker-controlled DHCP request data, not local configuration. The destination buffer is a fixed 256-byte stack array. The vulnerable loop can execute once per byte of the client-supplied Parameter Request List and appends duplicate classless route codes without checking whether they are already present. This creates attacker-triggered stack memory corruption during DHCP response construction.

## Fix Requirement

Deduplicate classless route Parameter Request List entries before appending them to `priority_list`, so each classless route option code is inserted at most once.

## Patch Rationale

The patch adds the same `stored_list` guard used by the normal request-list pass to the classless-route priority pass. This preserves RFC 3442 priority ordering for classless route options while preventing duplicate classless route bytes from repeatedly increasing `priority_len`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/dhcpd/options.c b/usr.sbin/dhcpd/options.c
index 80c5016..a395c12 100644
--- a/usr.sbin/dhcpd/options.c
+++ b/usr.sbin/dhcpd/options.c
@@ -242,8 +242,9 @@ create_priority_list(unsigned char *priority_list, unsigned char *prl,
 		prl_len = 0;
 	for(i = 0; i < prl_len; i++) {
 		/* CLASSLESS routes always have priority, sayeth RFC 3442. */
-		if (prl[i] == DHO_CLASSLESS_STATIC_ROUTES ||
-		    prl[i] == DHO_CLASSLESS_MS_STATIC_ROUTES) {
+		if ((prl[i] == DHO_CLASSLESS_STATIC_ROUTES ||
+		    prl[i] == DHO_CLASSLESS_MS_STATIC_ROUTES) &&
+		    !stored_list[prl[i]]) {
 			priority_list[priority_len++] = prl[i];
 			stored_list[prl[i]] = 1;
 		}
```