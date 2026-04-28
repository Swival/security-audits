# Out-of-Bounds Scoreboard Read

## Classification

Memory safety, medium severity.

## Affected Locations

`server/mpm/mpmt_os2/mpmt_os2.c:297`

## Summary

The OS/2 MPM parent process can read past the end of the scoreboard parent array while reaping terminated descendants. The lookup loop compares `ap_scoreboard_image->parent[slot].pid` before verifying that `slot` is within `HARD_SERVER_LIMIT`, so an unmatched PID advances `slot` to `HARD_SERVER_LIMIT` and then dereferences `parent[HARD_SERVER_LIMIT]`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`DosWaitChild()` returns a `child_pid` that is not present in any `ap_scoreboard_image->parent[slot].pid` entry.

## Proof

The parent reaping path receives `child_pid` from:

```c
rc = DosWaitChild(DCWA_PROCESSTREE, DCWW_NOWAIT, &proc_rc, &child_pid, 0);
```

When `rc == 0`, the code searches for the matching scoreboard slot:

```c
for (slot=0; ap_scoreboard_image->parent[slot].pid != child_pid && slot < HARD_SERVER_LIMIT; slot++);
```

Because C evaluates `&&` operands left to right, `ap_scoreboard_image->parent[slot].pid` is read before `slot < HARD_SERVER_LIMIT` is checked. If no slot matches, `slot` reaches `HARD_SERVER_LIMIT`, and the next loop-condition evaluation reads `parent[HARD_SERVER_LIMIT]`.

The scoreboard parent array is allocated for exactly `server_limit` entries. The OS/2 MPM hard limit is `HARD_SERVER_LIMIT`, and there is no sentinel slot after the valid range.

A practical unmatched PID source exists in the tree: `spawn_child()` records only Apache child process PIDs into `parent[slot].pid`, while CGI execution can create subprocesses through `mod_cgi` via `run_cgi_child()` and `ap_os_create_privileged_process()`. Those subprocesses are descendants observed by `DosWaitChild(DCWA_PROCESSTREE, ...)` but are not recorded in the MPM parent scoreboard slots.

## Why This Is A Real Bug

This is a real out-of-bounds read in the long-running parent process. The array bounds check exists but is ordered after the dereference, making it ineffective for the terminal unmatched case. Any reported descendant termination whose PID is absent from the scoreboard can trigger the read past the allocated parent array. Consequences depend on adjacent memory layout and include undefined behavior or parent process crash during child reaping.

## Fix Requirement

Check `slot < HARD_SERVER_LIMIT` before indexing `ap_scoreboard_image->parent[slot]`.

## Patch Rationale

The patch preserves the existing linear search behavior but reorders the loop condition so the bounds predicate is evaluated first:

```c
for (slot=0; slot < HARD_SERVER_LIMIT && ap_scoreboard_image->parent[slot].pid != child_pid; slot++);
```

With this ordering, `parent[slot]` is accessed only for valid slots `0` through `HARD_SERVER_LIMIT - 1`. If no match exists, `slot` becomes `HARD_SERVER_LIMIT`, the loop exits, and the existing `if (slot < HARD_SERVER_LIMIT)` guard prevents scoreboard mutation.

## Residual Risk

None

## Patch

```diff
diff --git a/server/mpm/mpmt_os2/mpmt_os2.c b/server/mpm/mpmt_os2/mpmt_os2.c
index b3adb03..8862474 100644
--- a/server/mpm/mpmt_os2/mpmt_os2.c
+++ b/server/mpm/mpmt_os2/mpmt_os2.c
@@ -293,7 +293,7 @@ static int master_main()
 
         if (rc == 0) {
             /* A child has terminated, remove its scoreboard entry & terminate if necessary */
-            for (slot=0; ap_scoreboard_image->parent[slot].pid != child_pid && slot < HARD_SERVER_LIMIT; slot++);
+            for (slot=0; slot < HARD_SERVER_LIMIT && ap_scoreboard_image->parent[slot].pid != child_pid; slot++);
 
             if (slot < HARD_SERVER_LIMIT) {
                 ap_scoreboard_image->parent[slot].pid = 0;
```