# Extra df Metric Triplets Index Past Row Array

## Classification

Out-of-bounds read. Severity: medium. Confidence: certain.

## Affected Locations

`usr.bin/snmp/snmpc.c:975`

## Summary

`snmpc_df()` allocates the `df` row array from the number of discovered `hrStorageDescr` rows, then processes later units/size/used metric responses without bounding the metric loop by that row count. An attacker-controlled SNMP agent can return extra complete metric triplets, causing the client to evaluate `df[i]` when `i == rows` and read past the allocated array.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A user runs `snmp df` against an attacker-controlled or malicious SNMP agent.

## Proof

The reproduced path is:

- `snmpc_df()` counts discovered descriptor rows and reallocates `df` for exactly `rows` entries at `usr.bin/snmp/snmpc.c:908`.
- It later requests units/size/used metric OIDs for the remaining rows.
- SNMP response parsing accepts valid returned varbind shapes; `snmp_resolve()` does not enforce that the response varbind count equals the request count.
- The metric-processing loop at `usr.bin/snmp/snmpc.c:975` was `for (j = 0; varbind != NULL; i++)`.
- Each accepted triplet uses `df[i].index`, `df[i].size`, `df[i].used`, `df[i].avail`, and `df[i].proc`.
- If a malicious agent appends more complete 3-varbind metric triplets than discovered rows, `i` reaches `rows` while `varbind != NULL`, and the loop reads `df[rows]`.

## Why This Is A Real Bug

The loop termination condition depended only on untrusted response length. The allocation size depended on previously discovered descriptor rows. Because those two quantities can diverge, the code allowed remote response data to drive `i` past the valid bounds of `df`. The first invalid access occurs before the loop naturally terminates, making this a concrete memory-safety violation and practical `snmp df` client crash/DoS condition.

## Fix Requirement

Metric response processing must stop before `i == rows`. Extra response varbind triplets from the agent must be ignored or rejected without accessing `df[i]`.

## Patch Rationale

The patch adds `i < rows` to the metric loop condition:

```c
for (j = 0; varbind != NULL && i < rows; i++) {
```

This preserves normal handling for expected metric triplets while preventing any iteration from accessing `df[i]` outside the allocated row array. Extra varbind triplets remain unprocessed once all known rows have been filled.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/snmp/snmpc.c b/usr.bin/snmp/snmpc.c
index 5f4596e..d40cf05 100644
--- a/usr.bin/snmp/snmpc.c
+++ b/usr.bin/snmp/snmpc.c
@@ -972,7 +972,7 @@ snmpc_df(int argc, char *argv[])
 					err(1, "Can't print response");
 			}
 		}
-		for (j = 0; varbind != NULL; i++) {
+		for (j = 0; varbind != NULL && i < rows; i++) {
 			if (ober_scanf_elements(varbind, "{oi}{oi}{oi}",
 			    &(reqoid[0]), &units, &(reqoid[1]), &size,
 			    &(reqoid[2]), &used, &varbind) == -1) {
```