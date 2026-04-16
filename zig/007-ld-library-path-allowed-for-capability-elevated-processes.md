# LD_LIBRARY_PATH honored in capability-elevated ElfDynLib loads

## Classification

- Type: Privilege escalation
- Severity: High
- Confidence: Certain

## Affected Locations

- `lib/std/dynamic_library.zig:206`
- Function: `ElfDynLib.resolveFromName`

## Summary

On Linux, `ElfDynLib.open(path, LD_LIBRARY_PATH)` suppresses `LD_LIBRARY_PATH` only when effective and real UID/GID differ. File-capability executables can run with elevated capabilities while UID/GID remain unchanged. In that case, attacker-controlled `LD_LIBRARY_PATH` is still searched for slashless library names, allowing a lower-privileged local user to cause an attacker-controlled ELF shared object to be mapped and later executed inside the capability-elevated process.

## Provenance

- Verified by Swival security analysis.
- Scanner: [Swival.dev Security Scanner](https://swival.dev)

## Preconditions

- Linux target using the `ElfDynLib` implementation.
- Executable has file capabilities or otherwise runs in Linux secure-execution mode without UID/GID changes.
- Caller invokes `ElfDynLib.open("libname.so", non_null_LD_LIBRARY_PATH)`.
- Library name contains no slash.
- Attacker controls a directory referenced by the supplied `LD_LIBRARY_PATH`.

## Proof

`ElfDynLib.open` calls `resolveFromName`. For slashless names, `resolveFromName` currently checks only:

```zig
std.os.linux.geteuid() == std.os.linux.getuid() and
std.os.linux.getegid() == std.os.linux.getgid()
```

If true, it searches the supplied `LD_LIBRARY_PATH`:

```zig
if (LD_LIBRARY_PATH) |ld_library_path| {
    if (resolveFromSearchPath(io, ld_library_path, path_or_name, ':')) |file| {
        return file;
    }
}
```

Practical trigger:

1. A Linux Zig executable using `ElfDynLib.open` is granted file capabilities, for example `cap_net_bind_service+ep`.
2. A lower-privileged local user launches it with `LD_LIBRARY_PATH=/attacker/dir`.
3. The executable passes that value as the non-null `LD_LIBRARY_PATH` argument to `ElfDynLib.open("libfoo.so", ...)`.
4. UID/GID are unchanged, so the current guard allows the search path.
5. `/attacker/dir/libfoo.so` is opened and mapped.
6. When the program looks up and calls a symbol, attacker code executes inside the capability-elevated process.

Caveat: `std.DynLib.open` passes `null` for `LD_LIBRARY_PATH` on the `ElfDynLib` path, so the issue is reachable through direct `ElfDynLib.open` / `ElfDynLib.openZ` use with a non-null `LD_LIBRARY_PATH`, not through that wrapper alone.

## Why This Is A Real Bug

Linux treats file-capability execution as privileged/secure execution even when real and effective UID/GID are equal. The previous guard modeled only setuid/setgid transitions and missed capability-based elevation.

The source itself documents that dynamic library loading trusts the selected file and that a malicious file can execute arbitrary code. Therefore, allowing attacker-controlled search paths in a capability-elevated process directly enables local privilege escalation into that process’s elevated capability context.

## Fix Requirement

`LD_LIBRARY_PATH` must be ignored whenever the process is running in Linux secure-execution mode, not merely when UID/GID differ. The guard must reject `LD_LIBRARY_PATH` when `AT_SECURE` is set.

## Patch Rationale

The patch adds an `AT_SECURE` check before honoring `LD_LIBRARY_PATH`:

```zig
std.os.linux.getauxval(std.elf.AT_SECURE) == 0
```

Linux sets `AT_SECURE` for secure-execution contexts, including file-capability elevation. This aligns `ElfDynLib` search behavior with the security expectation that environment-controlled library paths are ignored for privileged execution.

The existing UID/GID checks are retained as defense-in-depth and for the original setuid/setgid suppression behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/dynamic_library.zig b/lib/std/dynamic_library.zig
index d7cea3b3cd..7ba76c8016 100644
--- a/lib/std/dynamic_library.zig
+++ b/lib/std/dynamic_library.zig
@@ -203,8 +203,9 @@ pub const ElfDynLib = struct {
             return Io.Dir.cwd().openFile(io, path_or_name, .{});
         }
 
-        // Only read LD_LIBRARY_PATH if the binary is not setuid/setgid
-        if (std.os.linux.geteuid() == std.os.linux.getuid() and
+        // Only read LD_LIBRARY_PATH if the binary is not running in secure-execution mode.
+        if (std.os.linux.getauxval(std.elf.AT_SECURE) == 0 and
+            std.os.linux.geteuid() == std.os.linux.getuid() and
             std.os.linux.getegid() == std.os.linux.getgid())
         {
             if (LD_LIBRARY_PATH) |ld_library_path| {
```