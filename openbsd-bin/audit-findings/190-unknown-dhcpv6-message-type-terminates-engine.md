# Unknown DHCPv6 Message Type Terminates Engine

## Classification

Denial of service, high severity, certain confidence.

## Affected Locations

`sbin/dhcp6leased/engine.c:788`

## Summary

A malicious DHCPv6 server on the local network can send an otherwise accepted DHCPv6 packet with an unknown `msg_type`. After option validation succeeds, `parse_dhcp()` reaches the default message-type switch arm and calls `fatalx()`, terminating the engine process and stopping DHCPv6 lease handling.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

The client accepts the packet's `CLIENTID`, `SERVERID`, and `IA_PD` options.

## Proof

`engine_dispatch_frontend()` handles `IMSG_DHCP` by copying attacker-supplied DHCP data into `imsg_dhcp` and passing it to `parse_dhcp()`.

`parse_dhcp()` validates packet length and required options, including accepted `CLIENTID`, `SERVERID`, and IA_PD/IA_PREFIX data matching configured IAIDs and prefix constraints. After these checks, it switches on `hdr.msg_type`.

Known client-only, relay-agent-only, advertise, reply, and reconfigure messages are handled or ignored. The default case for an unknown message type calls:

```c
fatalx("%s: %s unhandled",
    __func__, dhcp_message_type2str(hdr.msg_type));
```

`fatalx()` exits the process with status 1. The parent does not respawn the engine; closure of the engine pipe causes event-loop exit and daemon shutdown.

Concrete trigger: a local-network malicious DHCPv6 server sends a packet to the client port with `msg_type` such as `14` or `255`, plus accepted `CLIENTID`, `SERVERID`, and `IA_PD` options. The engine deterministically exits.

Relevant reproduced locations include `sbin/dhcp6leased/engine.c:790`, `sbin/dhcp6leased/engine.c:797`, `sbin/dhcp6leased/engine.c:821`, `sbin/dhcp6leased/engine.c:874`, `sbin/dhcp6leased/engine.c:897`, `sbin/dhcp6leased/engine.c:960`, `sbin/dhcp6leased/log.c:191`, `sbin/dhcp6leased/dhcp6leased.c:511`, `sbin/dhcp6leased/dhcp6leased.c:598`, and `sbin/dhcp6leased/dhcp6leased.c:333`.

## Why This Is A Real Bug

Unknown DHCPv6 message types are attacker-controlled network input and should be rejected as invalid or unsupported protocol data. Treating them as an internal invariant violation via `fatalx()` converts a malformed but syntactically accepted packet into deterministic process termination.

The impact is practical because the attacker only needs local-network DHCPv6 server capability and accepted DHCPv6 options. No memory corruption or race condition is required.

## Fix Requirement

Replace the default `fatalx()` path for unknown DHCPv6 message types with packet rejection that logs a warning and returns without changing lease state.

## Patch Rationale

The patch changes the default `hdr.msg_type` switch arm in `parse_dhcp()` from process termination to graceful rejection:

```diff
-       fatalx("%s: %s unhandled",
+       log_warnx("%s: Ignoring unknown message type (%s) from server",
            __func__, dhcp_message_type2str(hdr.msg_type));
-       break;
+       goto out;
```

This preserves visibility through logging while preventing attacker-controlled protocol input from terminating the engine. The behavior now matches nearby handling for client-only, relay-agent-only, unexpected, and reconfigure messages, which are ignored rather than fatal.

## Residual Risk

None

## Patch

`190-unknown-dhcpv6-message-type-terminates-engine.patch` applies to `sbin/dhcp6leased/engine.c` and replaces the unknown DHCPv6 message-type `fatalx()` with `log_warnx()` plus `goto out`.