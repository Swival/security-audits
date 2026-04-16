# mprotect Wrapper Truncates Unaligned Protection Ranges

## Classification

Security control failure. Severity: high. Confidence: certain.

## Affected Locations

- `lib/c/sys/mman.zig:47`
- Musl libc target exported symbols:
  - `mprotect`
  - `__mprotect`

## Summary

The musl `mprotect` wrapper rounds the input address down to a page boundary but only rounds `len` up to a page boundary. For an unaligned address whose requested range crosses into an additional page, the syscall length is too short. The wrapper can return success while leaving the tail page with its previous permissions.

## Provenance

Verified by Swival security analysis and reproduction.

Scanner: https://swival.dev

## Preconditions

- The target uses musl libc.
- The exported `mprotect` / `__mprotect` symbol resolves to `mprotectLinux`.
- A caller passes an unaligned address and a length that crosses a page boundary.

## Proof

Affected code computed:

```zig
const page_size = std.heap.pageSize();
const start = std.mem.alignBackward(usize, @intFromPtr(addr), page_size);
const aligned_len = std.mem.alignForward(usize, len, page_size);
return errno(std.os.linux.mprotect(@ptrFromInt(start), aligned_len, @bitCast(prot)));
```

For page size `P`, address `page_aligned_addr + 1`, and length `P`, the requested range is:

```text
[page_aligned_addr + 1, page_aligned_addr + 1 + P)
```

That range crosses into the next page, so the normalized syscall must cover:

```text
[page_aligned_addr, page_aligned_addr + 2P)
```

The old code instead computed:

```text
start       = page_aligned_addr
aligned_len = alignForward(P, P) = P
```

So the actual syscall was:

```text
mprotect(page_aligned_addr, P, prot)
```

This protects only the first page. The tail page remains unchanged. If the shortened syscall succeeds, `errno(...)` reports success, so the exported `mprotect` reports success even though the full requested range was not protected.

## Why This Is A Real Bug

`mprotect` is a memory-protection control. A successful return is expected to mean the requested memory interval has had the requested protections applied. The wrapper accepts and normalizes an unaligned address by rounding the address down, but it failed to include the address offset in the rounded length.

As a result, callers can receive success while executable, writable, or otherwise sensitive permissions remain active on the trailing page. This is a fail-open protection error.

## Fix Requirement

When rounding an unaligned range for the syscall, compute the aligned length from the page-aligned start to the end of the original requested range:

```text
alignForward((addr - start) + len, page_size)
```

not:

```text
alignForward(len, page_size)
```

## Patch Rationale

The patch adds the page offset of `addr` relative to `start` before rounding the length up. This makes the syscall cover every page intersecting the original requested interval.

For the reproduced case:

```text
addr = page_aligned_addr + 1
len  = P
```

the patched calculation is:

```text
addr - start + len = 1 + P
alignForward(1 + P, P) = 2P
```

so the syscall covers both affected pages.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/c/sys/mman.zig b/lib/c/sys/mman.zig
index 3783cc4197..1cfece5e5b 100644
--- a/lib/c/sys/mman.zig
+++ b/lib/c/sys/mman.zig
@@ -44,7 +44,7 @@ fn mlockallLinux(flags: c_int) callconv(.c) c_int {
 fn mprotectLinux(addr: *anyopaque, len: usize, prot: c_int) callconv(.c) c_int {
     const page_size = std.heap.pageSize();
     const start = std.mem.alignBackward(usize, @intFromPtr(addr), page_size);
-    const aligned_len = std.mem.alignForward(usize, len, page_size);
+    const aligned_len = std.mem.alignForward(usize, @intFromPtr(addr) - start + len, page_size);
     return errno(std.os.linux.mprotect(@ptrFromInt(start), aligned_len, @bitCast(prot)));
 }
 
```