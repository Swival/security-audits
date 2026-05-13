# LockingTextReader destructor null-dereferences closed file handle

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `std/stdio.d:2924`

## Summary
`LockingTextReader` can retain a buffered character in `_front` with `_hasChar == true`, then later run its destructor after the underlying shared `File` implementation has been detached or closed. The destructor unconditionally calls `ungetc(_front, cast(FILE*)_f._p.handle)` before checking whether the file is still open, so a null `handle` is dereferenced and the process crashes.

## Provenance
- Verified from the provided finding and local reproduction
- Scanner source: https://swival.dev

## Preconditions
- A `LockingTextReader` instance buffers a character, setting `_hasChar = true`
- The underlying shared `File` handle is closed or detached before `LockingTextReader` destruction

## Proof
A local PoC reproduced the crash:
```d
import std.stdio;
import std.file;
import object : destroy;

void main() {
    auto path = "/tmp/ltr_close_poc.txt";
    std.file.write(path, cast(const void[]) "a");
    scope(exit) if (exists(path)) remove(path);

    auto f = File(path, "r");
    auto ltr = LockingTextReader(f);
    auto ch = ltr.front;
    f.close();
    destroy(ltr);
}
```

Observed result:
- Built against the checked-out tree with `ldc2 -I.`
- Running the binary produced `Segmentation fault: 11`

Root cause:
- `front` buffers one character and leaves `_hasChar = true`
- `f.close()` nulls the shared `Impl.handle`
- `~this()` executes `ungetc(_front, cast(FILE*)_f._p.handle)` without an `_f.isOpen` guard
- `ungetc` receives a null `FILE*`, causing the crash

## Why This Is A Real Bug
This is reachable through the public `LockingTextReader` API without undefined setup or private state manipulation. `LockingTextReader` aliases a `File` by shared implementation, so closing the aliased `File` invalidates the handle seen by the reader. Destructor-time null dereference is memory-unsafe process-crashing behavior and therefore a real high-severity lifecycle bug.

## Fix Requirement
The destructor must not call `ungetc` unless the underlying file is still open. An equivalent safe fix is to clear `_hasChar` before any path that destroys or detaches `_f`.

## Patch Rationale
The patch adds an open-handle guard before attempting `ungetc` in `LockingTextReader` destruction. This preserves the intended pushback behavior for valid live files while making destruction a no-op for already-closed or detached files, eliminating the null dereference with minimal behavioral change.

## Residual Risk
None

## Patch
Patched in `005-lockingtextreader-destructor-dereferences-null-after-eof-det.patch`.