# Column count wraps on 256th register rule

## Classification
- Type: data integrity bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/debug/Dwarf/Unwind/VirtualMachine.zig:60`
- `lib/std/debug/Dwarf/Unwind/VirtualMachine.zig:91`
- `lib/std/debug/Dwarf/Unwind/VirtualMachine.zig:122`
- `lib/std/debug/Dwarf/Unwind/VirtualMachine.zig:149`

## Summary
`ColumnRange.len` is stored as `u8` while `getOrAddColumn` can append an unbounded number of distinct register rules from attacker-controlled DWARF unwind instructions. On the 256th distinct register rule in one row, the length overflows and the row’s visible column slice becomes empty or truncated even though backing storage still contains entries.

## Provenance
- Reproduced from the verified report against the checked-in source tree
- Trigger path is attacker-controlled DWARF CFA input parsed by `evalInstructions`
- Reference: https://swival.dev

## Preconditions
- 256 distinct register rules are added to a single unwind row

## Proof
- `evalInstructions` processes DWARF CFA opcodes and calls `getOrAddColumn` for new register rules.
- In `getOrAddColumn`, `current_row.columns.len` is incremented before appending a new column.
- Because `ColumnRange.len` is `u8`, the 256th increment wraps from `255` to `0` in unchecked builds, and overflows with panic in checked builds.
- `.last_row.cols` snapshots this wrapped length at `lib/std/debug/Dwarf/Unwind/VirtualMachine.zig:122` and `lib/std/debug/Dwarf/Unwind/VirtualMachine.zig:125`.
- `runTo` reconstructs row state from that corrupted length at `lib/std/debug/Dwarf/Unwind/VirtualMachine.zig:149` and `lib/std/debug/Dwarf/Unwind/VirtualMachine.zig:156`, propagating the corruption.
- A minimal PoC using 256 extended `DW_CFA_same_value` instructions causes `zig run --zig-lib-dir lib` to panic with integer overflow at `lib/std/debug/Dwarf/Unwind/VirtualMachine.zig:91`.
- The same PoC under `zig run -OReleaseFast --zig-lib-dir lib` completes and reports `duped_cols=0`, confirming silent wrap and truncation in unchecked builds.

## Why This Is A Real Bug
The bug is reachable through untrusted unwind metadata, not a synthetic internal-only state. It causes a checked-build denial of service via overflow panic and, in unchecked builds, silently drops row register rules after wrap. That directly breaks unwind rule integrity and can miscompute frame recovery state for later execution.

## Fix Requirement
Replace the `u8` row column count with a non-wrapping size such as `usize`, or reject any attempt to grow past `maxInt(u8)` before mutating row state.

## Patch Rationale
Using a non-truncating length matches the actual storage model: the backing `columns` list already supports more than 255 entries, and row reconstruction logic depends on the recorded length being exact. This removes both the checked-build overflow and the unchecked-build silent corruption without changing intended semantics for valid inputs.

## Residual Risk
None

## Patch
- Patch file: `089-column-count-wraps-on-256th-register-rule.patch`
- The patch updates row column-length tracking so the per-row count no longer wraps on the 256th distinct register rule, preserving correct slices during row snapshotting and reconstruction.