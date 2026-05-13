# Unchecked TZif abbreviation index reads beyond abbreviation table

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `std/datetime/timezone.d:1489`

## Summary
`PosixTimeZone.getTimeZone` consumes `tt_abbrind` from each parsed TZif `TempTTInfo` and uses it as the start of an abbreviation slice. The parser validates several header counts, but it does not reject `tt_abbrind` values outside the declared abbreviation table. A crafted TZif can therefore make timezone loading read abbreviation bytes from outside `tzAbbrevChars`, leading to corrupted timezone names or an exception-driven denial of service.

## Provenance
- Verified by local reproduction against the affected parser path
- Patched in `042-unchecked-abbreviation-index-slices-parsed-tzfile-buffer.patch`
- Scanner source: https://swival.dev

## Preconditions
- Attacker controls parsed TZif file contents

## Proof
A malformed TZif with a 1-byte abbreviation table and an out-of-range `tt_abbrind` reaches the abbreviation construction path in `PosixTimeZone.getTimeZone`.
The parser accepts the file because it checks type counts but not whether `tt_abbrind < tzh_charcnt`.
At `std/datetime/timezone.d:1489`, the code slices from `tzAbbrevChars[tempTTInfo.tt_abbrind .. $]`.
With the crafted input:
- one execution path produced a bogus `stdName` containing non-table bytes such as `0x08 0x09 0x01`, demonstrating out-of-bounds abbreviation consumption during load
- another execution path advanced into `abbrevChars.countUntil('\0')` and failed with a wrapped `UnicodeException`, rethrown as `DateTimeException` at `std/datetime/timezone.d:2402`

These outcomes confirm the unchecked index is reachable and affects runtime behavior with attacker-controlled TZif input.

## Why This Is A Real Bug
The on-disk TZif format declares the abbreviation table length separately from each `tt_abbrind` offset. Using `tt_abbrind` without validating it against that declared table length violates the format's trust boundary. Reproduction showed both data integrity impact, where timezone abbreviations are derived from bytes outside the table, and availability impact, where parsing fails with an exception. Because the bug occurs during file parsing and is attacker-controlled, it is not theoretical.

## Fix Requirement
Reject any `TempTTInfo` entry whose `tt_abbrind` is greater than or equal to `tzAbbrevChars.length` before constructing the abbreviation slice.

## Patch Rationale
The patch adds an explicit bounds check on `tt_abbrind` before slicing `tzAbbrevChars`. Invalid TZif entries now fail closed during parsing instead of letting abbreviation parsing consume unrelated bytes or crash later in downstream string handling. This is the narrowest correct fix because the vulnerability is caused by missing validation at the point the untrusted offset first becomes dangerous.

## Residual Risk
None

## Patch
```diff
diff --git a/std/datetime/timezone.d b/std/datetime/timezone.d
index 0000000..0000000 100644
--- a/std/datetime/timezone.d
+++ b/std/datetime/timezone.d
@@ -1486,6 +1486,10 @@
         foreach (ttind, ref tempTTInfo; tempTTInfos)
         {
+            if (tempTTInfo.tt_abbrind >= tzAbbrevChars.length)
+                throw new DateTimeException(
+                    "TZ database file is corrupt. Invalid abbreviation index.");
+
             immutable abbrevChars = tzAbbrevChars[tempTTInfo.tt_abbrind .. $];
             immutable abbrevLength = abbrevChars.countUntil('\0');
             immutable tzAbbrev = cast(string) abbrevChars[0 .. abbrevLength].idup;
```