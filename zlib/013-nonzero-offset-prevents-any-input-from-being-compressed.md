# Nonzero offset breaks `Deflater.Add` slice handling

## Classification
- Type: logic error
- Severity: high
- Confidence: certain

## Affected Locations
- `contrib/dotzlib/DotZLib/Deflater.cs:52`

## Summary
`Deflater.Add(byte[] data, int offset, int count)` initializes `inputIndex` from `offset` but bounds its processing loop with `count` alone. As a result, any valid call where `offset >= count` compresses zero bytes, and any call where `0 < offset < count` compresses only a truncated prefix of the requested slice. This causes silent data loss and malformed compressed output for normal API usage with nonzero offsets.

## Provenance
- Verified from the reported finding and reproducer against the repository source
- Source file: `contrib/dotzlib/DotZLib/Deflater.cs`
- Scanner reference: https://swival.dev

## Preconditions
- `Deflater.Add` is called with a valid nonzero `offset`
- The caller provides a valid slice, i.e. `offset + count <= data.Length`

## Proof
In `Deflater.Add`, the method sets:
```csharp
int total = count;
int inputIndex = offset;
```

The main processing loop then runs only while:
```csharp
while (inputIndex < total)
```

For a valid call such as `Add(buf, 100, 20)`:
- `inputIndex = 100`
- `total = 20`
- `100 < 20` is false

Therefore:
- `copyInput(...)` is never called
- `deflate(...)` is never called
- no requested input bytes are compressed

The reproduced case also shows truncation for partially overlapping bounds. For `Add(buf, 5, 10)`, the method should consume 10 bytes starting at `buf[5]`, but `inputIndex < total` allows progress only until index `10`, so at most 5 bytes are processed.

## Why This Is A Real Bug
This is reachable through the public API using ordinary slice semantics. In .NET, `(buffer, offset, count)` conventionally means “process `count` bytes starting at `offset`,” and valid callers commonly pass nonzero offsets. The current implementation instead treats `count` as an absolute end index, which is inconsistent with the method contract and directly causes missing compressed data. The failure is silent: the method returns after updating checksum state, leaving callers with incomplete or empty compressed output.

## Fix Requirement
The loop must process exactly `count` bytes starting at `offset`. This requires using an absolute end index of `offset + count`, or equivalently tracking remaining bytes independently from the absolute buffer index.

## Patch Rationale
The patch changes the loop bound to match slice semantics by comparing `inputIndex` against the end of the requested segment rather than against `count` alone. This preserves existing buffering and deflate behavior while ensuring all requested bytes are copied and compressed regardless of nonzero offset.

## Residual Risk
None

## Patch
Applied in `013-nonzero-offset-prevents-any-input-from-being-compressed.patch`.