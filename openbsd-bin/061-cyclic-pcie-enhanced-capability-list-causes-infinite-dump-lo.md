# Cyclic PCIe Enhanced Capability List Causes Infinite Dump Loop

## Classification

Denial of service, medium severity, confidence: certain.

## Affected Locations

`usr.sbin/pcidump/pcidump.c:699`

## Summary

`dump_pcie_enhanced_caplist()` traverses attacker-controlled PCIe enhanced capability `next` pointers without cycle detection or an iteration/config-space bound. A malicious PCIe device can return an enhanced capability header whose `next` pointer targets the same or an earlier offset, causing verbose `pcidump` to loop indefinitely.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

An operator runs verbose `pcidump` against a malicious PCIe device attached to the host.

## Proof

Verbose dumping calls `dump_caplist()`, which invokes `dump_pcie_enhanced_caplist()` when it encounters `PCI_CAP_PCIEXPRESS`.

Inside `dump_pcie_enhanced_caplist()`:

- The traversal starts at `PCI_PCIE_ECAP`.
- Each header is read from device-controlled PCI configuration space using `pci_read()`.
- The function prints the enhanced capability.
- It advances with `ptr = PCI_PCIE_ECAP_NEXT(reg)`.
- The loop exits only when `ptr == PCI_PCIE_ECAP_LAST` or a `pci_read()` fails.

There was no visited-offset check, no iteration bound, no monotonicity check, and no config-space-size bound before the patch. A malicious device can return a non-terminating enhanced capability header whose `PCI_PCIE_ECAP_NEXT(reg)` extracts to the same offset, so the same header is read and printed forever.

## Why This Is A Real Bug

The loop termination condition depends on PCIe enhanced capability metadata returned by the device. That metadata is attacker-controlled for a malicious device. Because repeated offsets were accepted, a self-referential or cyclic enhanced capability list keeps `ptr` nonzero and non-last indefinitely. The process consumes CPU and repeatedly performs config reads/output, so `pcidump -v` never completes diagnostics.

## Fix Requirement

Bound traversal and reject repeated enhanced capability offsets.

## Patch Rationale

The patch adds a `seen` bitmap covering the 4 KiB PCI configuration space address range and checks each enhanced capability offset before reading it:

```c
u_int8_t seen[0x1000] = { 0 };

if (ptr >= nitems(seen) || seen[ptr])
	return;
seen[ptr] = 1;
```

This prevents both out-of-range offsets and cycles. A self-loop or any repeated enhanced capability offset now terminates traversal before the repeated read, so malicious cyclic lists cannot cause an infinite dump loop.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/pcidump/pcidump.c b/usr.sbin/pcidump/pcidump.c
index b19e467..b91e589 100644
--- a/usr.sbin/pcidump/pcidump.c
+++ b/usr.sbin/pcidump/pcidump.c
@@ -668,10 +668,15 @@ dump_pcie_enhanced_caplist(int bus, int dev, int func)
 	u_int32_t capidx;
 	u_int16_t ptr;
 	u_int16_t ecap;
+	u_int8_t seen[0x1000] = { 0 };
 
 	ptr = PCI_PCIE_ECAP;
 
 	do {
+		if (ptr >= nitems(seen) || seen[ptr])
+			return;
+		seen[ptr] = 1;
+
 		if (pci_read(bus, dev, func, ptr, &reg) != 0)
 			return;
```
