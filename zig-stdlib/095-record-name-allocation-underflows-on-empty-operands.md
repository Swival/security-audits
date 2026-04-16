# Record name allocation underflows on empty operands

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/zig/llvm/BitcodeReader.zig:302`
- `lib/std/zig/llvm/BitcodeReader.zig:358`
- `lib/std/zig/llvm/BitcodeReader.zig:362`

## Summary
`parseBlockInfoBlock` accepts a malformed `SETRECORDNAME` record with zero operands when `keep_names` is enabled. In that path, it computes `record.operands.len - 1` before validating operand presence. With `record.operands.len == 0`, this underflows: checked builds trap on integer overflow, while `ReleaseFast` wraps to `maxInt(usize)` and the allocator returns `error.OutOfMemory`. The result is a reliable parser denial of service on attacker-controlled bitcode.

## Provenance
- Verified from the supplied finding and reproducer against `lib/std/zig/llvm/BitcodeReader.zig`
- Root cause analysis and patch derived from local code inspection of the affected parser path
- Reference: [Swival Security Scanner](https://swival.dev)

## Preconditions
- `keep_names` is enabled
- Parsing is inside the `BLOCKINFO` block
- A valid `SETBID` record has already set `block_id`
- A `SETRECORDNAME` record is supplied with zero operands

## Proof
`nextRecord` exposes record operands as `operands.items[1..]`, so a malformed record can legitimately yield `record.operands.len == 0`.

In `parseBlockInfoBlock`, the `Block.Info.set_record_name_id` branch is reachable after `block_id` is set. That branch allocates the destination buffer using `record.operands.len - 1` and later relies on `record.operands[0]`. No prior guard rejects the empty-operands case.

Observed behavior:
- Checked builds: `record.operands.len - 1` triggers an integer-overflow panic
- `ReleaseFast`: subtraction wraps to `maxInt(usize)`, then `allocator.alloc` fails with `error.OutOfMemory`

This is a reproducible malformed-input crash/fatal parse abort before any operand validation.

## Why This Is A Real Bug
The fault is externally triggerable through attacker-controlled bitcode and occurs on a parser hot path before semantic validation. The failure mode is deterministic and build-dependent, but harmful in both cases:
- debug/safe configurations abort on overflow
- optimized configurations terminate parsing with fatal allocation failure

Because the bug is caused by missing input validation and is reachable under realistic parser settings (`keep_names`), it is a genuine denial-of-service vulnerability, not a theoretical edge case.

## Fix Requirement
Reject `SETRECORDNAME` records with zero operands before any subtraction or indexing of `record.operands`. The validation must run before computing `record.operands.len - 1` and before reading `record.operands[0]`.

## Patch Rationale
The patch adds an explicit `record.operands.len == 0` check in the `SETRECORDNAME` handling path and returns a parse error immediately for malformed input. This removes the underflow source, prevents invalid indexing, and preserves existing behavior for valid records without changing name decoding logic.

## Residual Risk
None

## Patch
- Patch file: `095-record-name-allocation-underflows-on-empty-operands.patch`
- Patched file: `lib/std/zig/llvm/BitcodeReader.zig`
- Change: add a zero-operands validation guard in the `Block.Info.set_record_name_id` branch before buffer allocation and operand access