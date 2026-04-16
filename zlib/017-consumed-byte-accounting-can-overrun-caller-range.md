# Inflater offset/count slice is under-consumed

## Classification
- Type: data integrity bug
- Severity: high
- Confidence: certain

## Affected Locations
- `contrib/dotzlib/DotZLib/Inflater.cs:59`

## Summary
`Inflater.Add(byte[] data, int offset, int count)` treats `count` as an absolute end index instead of a slice length. With a non-zero `offset`, the loop bound becomes `offset < count`, so the method either skips processing entirely or copies only `count - offset` bytes instead of the full caller-requested slice. This can truncate incremental decompression and corrupt stream processing.

## Provenance
- Verified from the provided reproducer and source review in `contrib/dotzlib/DotZLib/Inflater.cs:59`
- Public API reachability confirmed via `contrib/dotzlib/DotZLib/CodecBase.cs:103`
- Existing tests do not cover the affected overload in `contrib/dotzlib/DotZLib/UnitTests.cs:234`
- Source: https://swival.dev

## Preconditions
- Caller invokes `Add` with a non-zero `offset`
- Caller expects `count` to be interpreted as the number of bytes in the provided slice

## Proof
In `contrib/dotzlib/DotZLib/Inflater.cs:59`, the method initializes:
```csharp
int err;
int inputIndex = offset;
int total = count;
```

It then loops on:
```csharp
while (inputIndex < total)
```

This is incorrect for an `(offset, count)` API, because the valid slice ends at `offset + count`, not `count`.

Concrete outcomes:
- `Add(buf, 10, 5)` never processes input because `10 < 5` is false.
- `Add(buf, 5, 10)` enters once, but `copyInput` receives only `10 - 5 = 5` bytes of availability, so half the requested 10-byte slice is silently ignored.

The bug is externally reachable because `Add` is exposed by the codec base API in `contrib/dotzlib/DotZLib/CodecBase.cs:103`.

## Why This Is A Real Bug
This is not a theoretical accounting issue. A caller using the documented slice-style overload can lose part or all of the compressed input whenever `offset != 0`. Because decompression state advances on incomplete input, the resulting behavior can include truncated output, inflate failures, or checksum mismatches depending on which compressed bytes are skipped. The issue occurs on normal incremental use and does not require invalid input.

## Fix Requirement
Compute the loop boundary as the end of the caller-provided slice and consume only within `[offset, offset + count)`. The method must interpret `count` as a length, not an absolute index.

## Patch Rationale
The patch changes the local bound from `count` to `offset + count`, preserving the intended offset/count contract without changing inflate semantics. This is the minimal correction needed to ensure the full requested slice is made available to zlib and no bytes are silently dropped when `offset` is non-zero.

## Residual Risk
None

## Patch
- `017-consumed-byte-accounting-can-overrun-caller-range.patch` updates `contrib/dotzlib/DotZLib/Inflater.cs` so the `Add(byte[] data, int offset, int count)` loop uses the correct slice end (`offset + count`) rather than treating `count` as an absolute bound.