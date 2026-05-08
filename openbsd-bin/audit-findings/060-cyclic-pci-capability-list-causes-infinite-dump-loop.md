# Cyclic PCI Capability List Causes Infinite Dump Loop

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

`usr.sbin/pcidump/pcidump.c:744`

## Summary

`pcidump -v` traverses a device-controlled legacy PCI capability list without detecting cycles. A malicious PCI device can make a capability next pointer refer to itself or an earlier capability, causing `dump_caplist()` to loop forever while repeatedly performing successful config-space reads.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

An operator runs `pcidump -v` against or across a malicious PCI device.

## Proof

The verbose path is reachable:

- `-v` sets `verbose`.
- `probe()` calls `dump()` when `verbose` is set.
- `dump()` calls `dump_caplist()` after dumping the header-specific fields.

The vulnerable traversal is in `dump_caplist()`:

- It checks `PCI_STATUS_CAPLIST_SUPPORT`.
- It reads the initial capability pointer.
- It loops while `ptr != 0`.
- Each iteration reads the capability header at `ptr`.
- It advances with `ptr = PCI_CAPLIST_NEXT(reg)`.

A malicious device can expose:

- `PCI_STATUS_CAPLIST_SUPPORT` set.
- Initial capability pointer `0x40`.
- A valid capability header at `0x40`.
- Capability next pointer also set to `0x40`.

Under those values, every `pci_read()` succeeds, `ptr` remains nonzero and unchanged, and the loop never terminates. This reproduces a CPU-consuming `pcidump -v` invocation that never completes diagnostics.

## Why This Is A Real Bug

PCI configuration space is device-controlled. The existing code trusts the legacy capability next pointer and has no visited-offset tracking, no cycle detection, and no iteration bound. The only exits are `ptr == 0` or `pci_read()` failure, neither of which occurs for a valid self-referential or cyclic capability list.

The impact is practical denial of service of the diagnostic tool invocation: an operator running `pcidump -v` against the malicious device gets a process that spins and never completes.

## Fix Requirement

The capability-list walker must stop on malformed traversal state, including:

- Repeated capability offsets.
- Unaligned capability offsets.
- Offsets outside valid legacy PCI capability header read range.

## Patch Rationale

The patch adds a `seen[256]` bitmap indexed by capability offset and checks each offset before reading it:

```c
if (ptr > 0xfc || (ptr & 0x03) || seen[ptr])
	return;
seen[ptr] = 1;
```

This prevents infinite traversal by terminating on repeat offsets, including self-loops and longer cycles. It also rejects unaligned offsets and offsets greater than `0xfc`, which cannot safely contain a 4-byte capability header in 256-byte legacy PCI configuration space.

The change preserves normal behavior for valid acyclic capability lists and only stops dumping when the device advertises malformed capability-list structure.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/pcidump/pcidump.c b/usr.sbin/pcidump/pcidump.c
index b19e467..127861f 100644
--- a/usr.sbin/pcidump/pcidump.c
+++ b/usr.sbin/pcidump/pcidump.c
@@ -703,7 +703,7 @@ void
 dump_caplist(int bus, int dev, int func, u_int8_t ptr)
 {
 	u_int32_t reg;
-	u_int8_t cap;
+	u_int8_t cap, seen[256] = { 0 };
 
 	if (pci_read(bus, dev, func, PCI_COMMAND_STATUS_REG, &reg) != 0)
 		return;
@@ -714,6 +714,9 @@ dump_caplist(int bus, int dev, int func, u_int8_t ptr)
 		return;
 	ptr = PCI_CAPLIST_PTR(reg);
 	while (ptr != 0) {
+		if (ptr > 0xfc || (ptr & 0x03) || seen[ptr])
+			return;
+		seen[ptr] = 1;
 		if (pci_read(bus, dev, func, ptr, &reg) != 0)
 			return;
 		cap = PCI_CAPLIST_CAP(reg);
```