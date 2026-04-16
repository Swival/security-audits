# Finish hides inflate failure by resetting state

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `contrib/dotzlib/DotZLib/Inflater.cs:75`

## Summary
`Inflater.Finish()` treats any nonzero `inflate()` return as loop termination, then unconditionally updates checksum state and calls `inflateReset(ref _ztream)`. If the final inflate step fails on malformed or truncated input, `Finish()` returns normally instead of throwing, which makes an invalid stream appear successfully finalized and destroys the native zlib error state.

## Provenance
- Verified from the supplied finding and reproducer against `contrib/dotzlib/DotZLib/Inflater.cs`
- Reference: https://swival.dev

## Preconditions
- `Finish()` is called after `inflate()` reports an error while consuming the final compressed bytes
- Input is malformed, truncated, or otherwise causes zlib to fail during finalization

## Proof
In `contrib/dotzlib/DotZLib/Inflater.cs`, `Finish()` loops on:
```csharp
err = ZLib.inflate(ref _ztream, FlushTypes.Z_FINISH);
if(err != 0) break;
```
After the loop, it proceeds to:
```csharp
_totalout += avail;
Checksum = _ztream.adler;
err = ZLib.inflateReset(ref _ztream);
```
Because the loop breaks on any nonzero code, zlib error returns are handled the same as expected completion. When malformed trailer or final block data causes `inflate()` to fail during `Finish()`, partial output may already have been emitted, no exception is raised, checksum is updated from the failed stream state, the inflater is reset, and the method returns normally. This reproduces the reported behavior that decompression failure is hidden and native diagnostic state is discarded.

## Why This Is A Real Bug
A caller expects `Finish()` to distinguish successful stream completion from decompression failure. The current behavior collapses both outcomes into normal return. That can cause invalid compressed data to be accepted as successfully processed, especially if partial output was already delivered through callbacks. The unconditional reset also erases zlib's failure context, preventing diagnosis or recovery from the actual native error.

## Fix Requirement
`Finish()` must inspect the final `inflate()` result and only reset the stream after the expected terminal success condition. Any zlib error during finish must throw and preserve failure semantics instead of silently returning.

## Patch Rationale
The patch makes `Finish()` accept only the expected end-of-stream result before updating checksum/final state and resetting the inflater. On any other return code, it throws immediately rather than resetting, so callers reliably observe malformed or truncated input as a failure and zlib error context is not silently discarded.

## Residual Risk
None

## Patch
- `018-finish-resets-stream-after-inflate-error.patch` updates `contrib/dotzlib/DotZLib/Inflater.cs`
- The change gates `inflateReset(ref _ztream)` behind successful `Z_STREAM_END` completion and throws on finish-time inflate errors
- This preserves existing successful-finalization behavior while preventing silent acceptance of invalid compressed streams