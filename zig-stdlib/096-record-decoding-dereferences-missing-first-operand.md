# Record decoding rejects empty operand lists

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/zig/llvm/BitcodeReader.zig:220`

## Summary
`nextRecord` decodes abbreviation operands into `operands`, then unconditionally reads `operands.items[0]` to populate the record id. If a malformed abbreviation yields zero operands, this violates the parser's non-empty-record invariant and triggers a bounds trap. The patch rejects empty decoded operand lists before dereferencing index `0`.

## Provenance
- Verified from the provided reproducer and finding details
- Swival Security Scanner: https://swival.dev

## Preconditions
- A decoded abbreviation produces zero operands for a record

## Proof
- `nextRecord` appends one entry per decoded abbreviation operand into `operands`
- For an abbreviation with zero operands, the decode loop performs zero iterations and `operands.items.len` remains `0`
- `.name` already tolerates this state by returning an empty slice when `len < 1`
- `.id` then evaluates `operands.items[0]` at `lib/std/zig/llvm/BitcodeReader.zig:220`
- This is an out-of-bounds access on an empty slice, causing a bounds-checked trap during record parsing
- The reproducer reaches this state by entering a nested block with attacker-controlled abbreviation width, defining an abbreviation with zero operands, and then emitting a record using that abbreviation

## Why This Is A Real Bug
The crash follows directly from parser-controlled state, not from a hypothetical misuse by callers. The decoder already accepts malformed bitcode far enough to create an empty-abbreviation record, and the failing access is on the normal parse path. This makes the issue a reachable denial of service against any consumer parsing untrusted bitcode.

## Fix Requirement
Reject empty decoded operand lists in `nextRecord` before any access to `operands.items[0]`, and return a parse error instead of trapping.

## Patch Rationale
The fix enforces the existing implicit invariant at the point where it matters most: immediately after operand decoding and before record construction. This preserves current behavior for valid records, matches the existing defensive handling of `.name`, and converts a runtime bounds trap into explicit malformed-input rejection.

## Residual Risk
None

## Patch
- Patch file: `096-record-decoding-dereferences-missing-first-operand.patch`
- Intended change: add a guard in `lib/std/zig/llvm/BitcodeReader.zig` so `nextRecord` errors out when `operands.items.len == 0` before reading the first operand