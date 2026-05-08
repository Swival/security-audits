# Short Relay-Reply Underflows Option Parser Length

## Classification

Denial of service, high severity, remotely triggerable.

## Affected Locations

`usr.sbin/dhcrelay6/dhcrelay6.c:523`

Primary vulnerable parser path:

`usr.sbin/dhcrelay6/dhcrelay6.c:604`

## Summary

A short DHCPv6 Relay-Reply received on a non-client relay interface can reach `relay6_poprelaymsg()` with only the generic DHCPv6 header length validated. `relay6_poprelaymsg()` then treats the buffer as a larger `struct dhcp6_relay_packet` and subtracts that larger header size from the packet length without first verifying that the packet is long enough. This underflows the remaining-length counter and allows the option parser to read beyond the received datagram, which can terminate the relay process.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A packet arrives on a non-client relay interface.
- The packet message type is `DHCP6_MT_RELAYREPL`.
- The packet length is at least `sizeof(struct dhcp6_packet)` but less than `sizeof(struct dhcp6_relay_packet)`.
- The sender is a remote DHCPv6 server, relay peer, or other host able to send on that non-client relay interface.

## Proof

`mcast6_recv()` receives attacker-controlled datagrams into `iovbuf[4096]` and passes `recvlen` to `relay6()`.

`relay6()` only checks:

```c
if (plen < (int)sizeof(*ds)) {
	log_debug("invalid packet size");
	return;
}
```

For `DHCP6_MT_RELAYREPL` on a non-client interface, `clientdir` is true and execution reaches:

```c
relay6_poprelaymsg(pc, &dstif, (uint8_t *)p, &buflen)
```

Inside `relay6_poprelaymsg()`, the buffer is immediately interpreted as:

```c
struct dhcp6_relay_packet *dsr = (struct dhcp6_relay_packet *)p;
```

The function then initializes:

```c
size_t pleft = *plen;
```

and later subtracts the full relay header size:

```c
dso = dsr->dsr_options;
pleft -= sizeof(*dsr);
```

For a short Relay-Reply such as `plen == 4`, `sizeof(struct dhcp6_packet)` is satisfied, but `sizeof(struct dhcp6_relay_packet)` is not. The subtraction underflows `pleft` to a very large `size_t`.

The option loop then treats memory beyond the received packet as DHCPv6 options:

```c
while (pleft > sizeof(*dso)) {
	optcode = ntohs(dso->dso_code);
	dsolen = sizeof(*dso) + ntohs(dso->dso_length);
```

This causes out-of-bounds reads past the actual datagram and can run beyond `iovbuf[4096]`, producing undefined behavior and relay termination.

## Why This Is A Real Bug

The parser uses a larger structure than the caller validated. The existing `relay6()` length check validates only `sizeof(struct dhcp6_packet)`, while `relay6_poprelaymsg()` requires `sizeof(struct dhcp6_relay_packet)` before accessing relay-header fields and before subtracting the relay-header length.

Because the length variable is unsigned, subtracting the larger relay-header size from a shorter packet does not become negative; it wraps to a large value. That defeats the parser’s remaining-length bound and permits reads outside the received DHCPv6 packet.

The attack is reachable remotely through the normal receive path and does not require local execution.

## Fix Requirement

Reject Relay-Reply packets before relay option parsing when:

```c
*plen < sizeof(struct dhcp6_relay_packet)
```

The check must happen in `relay6_poprelaymsg()` before dereferencing relay-header-only fields or subtracting `sizeof(*dsr)` from the remaining length.

## Patch Rationale

The patch adds an early size guard in `relay6_poprelaymsg()`:

```c
if (*plen < sizeof(*dsr)) {
	log_debug("invalid relay-message size");
	return -1;
}
```

This ensures the fixed Relay-Reply header is present before:

- reading relay-header fields such as `dsr_peer` and `dsr_linkaddr`;
- setting `dso = dsr->dsr_options`;
- subtracting `sizeof(*dsr)` from `pleft`;
- entering the DHCPv6 option parser.

With this guard, short Relay-Reply packets are rejected cleanly and cannot underflow `pleft`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/dhcrelay6/dhcrelay6.c b/usr.sbin/dhcrelay6/dhcrelay6.c
index f566486..5c8b924 100644
--- a/usr.sbin/dhcrelay6/dhcrelay6.c
+++ b/usr.sbin/dhcrelay6/dhcrelay6.c
@@ -590,6 +590,11 @@ relay6_poprelaymsg(struct packet_ctx *pc, struct interface_info **intf,
 
 	*intf = NULL;
 
+	if (*plen < sizeof(*dsr)) {
+		log_debug("invalid relay-message size");
+		return -1;
+	}
+
 	/* Sanity check: this is a relay message of the right type. */
 	if (dsr->dsr_msgtype != DHCP6_MT_RELAYREPL) {
 		log_debug("Invalid relay-message (%s) to pop",
```