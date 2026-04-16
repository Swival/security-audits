# WASI Dir.access Fails Open for Execute Permission

## Classification

security_control_failure, critical severity.

## Affected Locations

- `lib/std/Io/Threaded.zig:1626`
- Concrete vulnerable implementation: `dirAccessWasi` in `lib/std/Io/Threaded.zig`

## Summary

On WASI targets without linked libc, `Dir.access` ignores `AccessOptions.execute`. An execute-only access check for an existing non-executable path returns success because the WASI rights mask remains zero and therefore trivially passes the inheriting-rights comparison.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `native_os == .wasi`
- `builtin.link_libc == false`
- Caller invokes WASI `Dir.access`
- Requested access includes `.execute = true`

## Proof

`dirAccess` dispatches to `dirAccessWasi` on WASI. In `dirAccessWasi`:

1. `wasi.path_filestat_get` verifies the target path exists.
2. If any access option is requested, it builds a `wasi.rights_t` mask.
3. Read requests map to `FD_READDIR` for directories or `FD_READ` for non-directories.
4. Write requests map to `FD_WRITE`.
5. Execute requests are not mapped; the source explicitly stated: `// No validation for execution.`
6. For execute-only checks, `rights` remains all zero.
7. The final comparison succeeds because `(0 & directory.fs_rights_inheriting) == 0`.
8. The function returns success instead of `error.AccessDenied`.

Runtime reproduction confirmed this on `wasm32-wasi` under `wasmtime --dir=.`:

- Created a host file with mode `-rw-r--r--`.
- Called `cwd.access(io, "nonexec_poc.txt", .{ .execute = true })`.
- The call returned success: `access_execute_success`.

## Why This Is A Real Bug

`Dir.AccessOptions.execute` is a real permission request, and `AccessDenied` is the documented denial result for requested access options. Other backends, such as POSIX, map execute to `X_OK`. The WASI backend cannot validate execute using available WASI rights, but it returned success anyway. This is a deterministic fail-open authorization check.

## Fix Requirement

When `options.execute` is requested on the WASI/no-libc backend, the implementation must not silently allow the request. Because WASI rights do not provide an executable permission bit for this check, the backend must conservatively return `error.AccessDenied`.

## Patch Rationale

The patch rejects execute access requests before the rights comparison. This prevents zero-right execute-only checks from succeeding and preserves existing read/write behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/Io/Threaded.zig b/lib/std/Io/Threaded.zig
index 90d74d4b37..dd196fe8a5 100644
--- a/lib/std/Io/Threaded.zig
+++ b/lib/std/Io/Threaded.zig
@@ -4188,7 +4188,8 @@ fn dirAccessWasi(
     if (options.write)
         rights.FD_WRITE = true;
 
-    // No validation for execution.
+    if (options.execute)
+        return error.AccessDenied;
 
     // https://github.com/ziglang/zig/issues/18882
     const rights_int: u64 = @bitCast(rights);
```