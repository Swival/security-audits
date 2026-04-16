# Unvalidated DWARF deref performs arbitrary raw memory reads

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/debug/Dwarf/expression.zig:399`
- `lib/std/debug/Dwarf/expression.zig:1010`
- `lib/std/debug/SelfInfo/Elf.zig:189`
- `lib/std/debug/SelfInfo/Elf.zig:271`
- `lib/std/debug/SelfInfo/Elf.zig:281`
- `lib/std/debug/SelfInfo/Elf.zig:297`
- `lib/std/debug/SelfInfo/MachO.zig:124`
- `lib/std/debug/SelfInfo/MachO.zig:501`
- `lib/std/debug/SelfInfo/MachO.zig:523`
- `lib/std/debug/SelfInfo/MachO.zig:525`

## Summary
`DW_OP_deref`-family handlers in the DWARF expression evaluator convert attacker-influenced stack integers into pointers with `@ptrFromInt(...)` and immediately read memory. In unwind/backtrace paths, loaded module DWARF expressions are evaluated without a validated memory access abstraction, so crafted expressions can perform arbitrary same-process raw reads.

## Provenance
- Verified from the supplied finding and reproducer.
- Reproduced against the affected code paths in the standard library unwind/DWARF evaluator.
- Reference: https://swival.dev

## Preconditions
- Attacker-controlled DWARF expression is evaluated.
- The expression reaches a permitted dereference opcode during evaluation or unwinding.

## Proof
- `run`/`step` interpret bytes from the untrusted DWARF expression.
- `OP.addr` plus arithmetic opcodes can place an attacker-chosen integer address on the evaluation stack.
- For `OP.deref`, `OP.xderef`, `OP.deref_size`, `OP.xderef_size`, `OP.deref_type`, and `OP.xderef_type`, the evaluator converts that integer to a pointer via `@ptrFromInt(addr)` and performs immediate loads of `u8`, `u16`, `u32`, or `u64`, with no provenance, mapping, or bounds validation.
- Existing tests intentionally dereference `@intFromPtr(&deref_target)`, proving the dereference path is reachable by design.
- In call frame evaluation, `isOpcodeValidInCFA` still permits `OP.deref`, `OP.xderef`, `OP.deref_size`, `OP.xderef_size`, and `OP.xderef_type`, so crafted unwind expressions from loaded ELF/Mach-O modules can trigger the read primitive during unwinding.

## Why This Is A Real Bug
The implementation performs direct raw memory reads from attacker-controlled addresses inside the current process. This is not speculative behavior: the opcode handlers explicitly materialize pointers from integers and dereference them, and unwind entry points evaluate expressions sourced from loaded binaries. That creates a concrete same-process arbitrary-read primitive during backtrace/unwind processing.

## Fix Requirement
Replace raw `@ptrFromInt` dereferences with a caller-supplied validated memory reader, and reject dereference opcodes when no trusted reader is available.

## Patch Rationale
The patch removes implicit raw process-memory dereferences from DWARF evaluation and routes dereference operations through an explicit, validated memory access interface. This preserves legitimate DWARF evaluation for trusted callers while preventing untrusted expressions from manufacturing arbitrary pointers and reading process memory during unwinding.

## Residual Risk
None

## Patch
- Patched in `082-unvalidated-dwarf-deref-performs-arbitrary-raw-memory-reads.patch`.
- The patch enforces validated memory reads for DWARF dereference opcodes and prevents unsafe fallback to direct `@ptrFromInt` loads in the affected evaluator path.