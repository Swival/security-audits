# small UEFI probes corrupt saved frame pointer

## Classification

Data integrity bug, medium severity.

## Affected Locations

`library/compiler-builtins/compiler-builtins/src/probestack.rs:204`

## Summary

The x86 UEFI `__rust_probestack` path can overwrite its saved caller frame pointer when LLVM requests a small probe size. For `eax == 4`, the return-address relocation writes to `[ebp]`, replacing the saved caller `ebp` with the return address. The function then restores `ebp` from corrupted stack state, breaking the caller frame chain and potentially causing a bad epilogue, crash, or control-flow failure.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Target is `x86` UEFI.
- `__rust_probestack` is called with `eax` between `1` and `4`.
- The reachable reproduced case is `eax == 4`, as ordinary LLVM dynamic alloca appears to round small requests to 4 bytes.

## Proof

At entry after the UEFI x86 prologue:

```text
[ebp + 4]  return address
[ebp + 0]  saved caller ebp
[ebp - 4]  saved ecx
[ebp - 8]  saved edx / current esp before sub
```

For `eax == ecx == 4`, execution takes the `jna 3f` path:

```asm
sub    esp, ecx              ; esp = ebp - 12
mov    edx, dword ptr [ebp + 4]
mov    dword ptr [esp + 12], edx
```

Because `esp == ebp - 12`, the destination `[esp + 12]` is exactly `[ebp]`. This overwrites the saved caller frame pointer with the return address.

The later epilogue used `leave`, which restores `esp` from `ebp` and pops the overwritten value into `ebp`. The probed caller can then continue with a corrupted frame pointer and may misrestore `esp` in its own epilogue.

## Why This Is A Real Bug

LLVM passes the requested probe size in `eax`, and the source comments explicitly state that dynamic stack allocation can trigger stack probes with sizes below `0x1000`. The UEFI implementation handles the `ecx <= 0x1000` case through the same final block that relocates the return address to `[esp + 12]`.

For small values, that relocation overlaps the stack-probe frame itself. In the reproduced `eax == 4` case, it overwrites saved `ebp`, violating the callee-saved/frame-pointer invariant. This is not limited to unwind metadata: generated callers using dynamic alloca can rely on `ebp` for their own epilogue, so corruption can cause an actual crash or control-flow breakage.

## Fix Requirement

The UEFI x86 probe must avoid losing the saved caller frame pointer when relocating the return address for small probe sizes. It must either handle `eax <= 4` without overlapping `[ebp]`, or preserve the saved caller `ebp` before the overlapping write and restore it explicitly afterward.

## Patch Rationale

The patch preserves the saved caller frame pointer before the potentially overlapping return-address relocation:

```asm
mov    ecx, dword ptr [ebp]
```

After the relocation and after restoring `edx`, it restores the frame pointer directly:

```asm
mov    ebp, ecx
```

Because `ecx` is used as temporary storage for saved `ebp`, the original `leave` sequence is replaced with an explicit stack adjustment:

```asm
pop    ecx
add    esp, 4
```

This discards the saved `ebp` stack slot without reloading from the potentially corrupted memory location. The function then continues with the existing UEFI behavior of subtracting `eax` from `esp` before returning.

## Residual Risk

None

## Patch

```diff
diff --git a/library/compiler-builtins/compiler-builtins/src/probestack.rs b/library/compiler-builtins/compiler-builtins/src/probestack.rs
index c4a2eeb0e01..2f93efd33e3 100644
--- a/library/compiler-builtins/compiler-builtins/src/probestack.rs
+++ b/library/compiler-builtins/compiler-builtins/src/probestack.rs
@@ -205,11 +205,13 @@
             sub    esp, ecx
             test   dword ptr [esp + 8], esp
             mov    edx, dword ptr [ebp + 4]
+            mov    ecx, dword ptr [ebp]
             mov    dword ptr [esp + 12], edx
             add    esp, eax
             pop    edx
+            mov    ebp, ecx
             pop    ecx
-            leave
+            add    esp, 4
 
             sub   esp, eax
             .cfi_def_cfa_register esp
```