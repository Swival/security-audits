# Division round-up overflows to zero before division

## Classification
- Type: logic error
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/common.d:223`
- `std/experimental/allocator/building_blocks/bitmapped_block.d:117`
- `std/experimental/allocator/building_blocks/bitmapped_block.d:169`
- `std/experimental/allocator/building_blocks/bitmapped_block.d:303`

## Summary
`divideRoundUp(size_t a, size_t b)` rounded with `(a + b - 1) / b` after only asserting `b != 0`. For `a` near `size_t.max`, `a + b - 1` wraps before division and can return `0` instead of the required ceiling quotient. In allocator sizing paths, this silently collapses requested near-max capacity to zero in release builds.

## Provenance
- Reproduced from the verified finding and runtime behavior described by the user
- Swival Security Scanner: https://swival.dev

## Preconditions
- `a` is near `size_t.max`
- `b > 0`

## Proof
For `a = size_t.max` and `b = 2`, the original helper computed:
```d
(a + b - 1) / b
= (size_t.max + 1) / 2
= 0 / 2
= 0
```

This is incorrect; the mathematical ceiling is `(size_t.max / 2) + 1`.

The reproduced allocator path confirmed the bug reaches real behavior:
- constructing `BitmappedBlock!(64, 8, LoggingAllocator)(..., size_t.max)` forwarded an allocation request of `0` to the parent allocator
- `_blocks` became `0` at `std/experimental/allocator/building_blocks/bitmapped_block.d:117`
- later `allocate(1)` used `s.divideRoundUp(blockSize)` at `std/experimental/allocator/building_blocks/bitmapped_block.d:303` and returned a null/empty slice

## Why This Is A Real Bug
This is not a theoretical overflow-only concern. The helper is used for allocator sizing, and the wrap changes allocator state from “near-max capacity requested” to “zero capacity allocated.” That produces silent under-allocation in release builds and observable misbehavior: construction succeeds, but subsequent allocation returns empty. The stateful-parent constructor path at `std/experimental/allocator/building_blocks/bitmapped_block.d:169` lacked the debug assertion present in the stateless path, so the bad size flowed through unchecked.

## Fix Requirement
Replace the overflow-prone round-up formula with one that cannot wrap for valid `b > 0`, such as:
```d
a / b + (a % b != 0)
```
and preserve the nonzero-divisor precondition.

## Patch Rationale
The patch updates `divideRoundUp` to compute the ceiling quotient via division and remainder instead of pre-adding `b - 1`. This removes the overflow condition while preserving semantics for all valid inputs. It directly fixes the reproduced path because near-max capacities now produce the correct nonzero block count instead of collapsing to zero.

## Residual Risk
None

## Patch
- Patch file: `053-division-round-up-can-wrap-before-division.patch`
- Patched location: `std/experimental/allocator/common.d:223`
- Change:
```diff
-    return (a + b - 1) / b;
+    return a / b + (a % b != 0);
```