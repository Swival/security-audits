# MaxTransfersPerUser Skips Matching Transfers

## Classification

Policy bypass, medium severity.

## Affected Locations

`modules/mod_xfer.c:416`

## Summary

`MaxTransfersPerUser` undercounts active transfers for the same user and command because the command comparison is inverted. Matching scoreboard entries are skipped instead of counted, allowing an authenticated user to exceed the configured per-user concurrent transfer cap.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`MaxTransfersPerUser` is configured for the requested transfer command, such as:

```apache
MaxTransfersPerUser RETR 1
```

## Proof

`xfer_pre_retr`, `xfer_pre_stor`, `xfer_pre_stou`, and `xfer_pre_appe` call `xfer_check_limit()` before allowing transfers.

Inside `xfer_check_limit()`, the `MaxTransfersPerUser` scoreboard loop filters entries by:

- same local server address
- same authenticated `session.user`
- matching transfer command

The third filter is inverted:

```c
if (strcmp(score->sce_cmd, xfer_cmd) == 0) {
  pr_trace_msg(trace_channel, 25,
    "MaxTransfersPerUser: command '%s' does not match '%s', skipping",
    xfer_cmd, score->sce_cmd);
  continue;
}

curr++;
```

For active transfers with the same command, `strcmp(...) == 0` is true, so the loop executes `continue` and does not increment `curr`.

The adjacent `MaxTransfersPerHost` logic uses the expected condition:

```c
if (strcmp(score->sce_cmd, xfer_cmd) != 0) {
  ...
  continue;
}

curr++;
```

Thus, an authenticated FTP user can open multiple sessions and start concurrent same-command transfers covered by `MaxTransfersPerUser`; existing same-command transfers are skipped, `curr` remains below `max`, and additional transfers are allowed.

## Why This Is A Real Bug

The directive is intended to enforce a per-user concurrent transfer cap for specific transfer commands. The implementation instead excludes the exact matching commands it should count. This directly bypasses an administrator-configured authorization/resource policy and is reachable through normal authenticated FTP behavior.

## Fix Requirement

Only skip scoreboard entries whose command differs from the configured transfer command. Count entries whose command matches.

## Patch Rationale

Changing `strcmp(score->sce_cmd, xfer_cmd) == 0` to `strcmp(score->sce_cmd, xfer_cmd) != 0` makes `MaxTransfersPerUser` consistent with `MaxTransfersPerHost` and with the trace message text. Matching same-user, same-server, same-command transfers now increment `curr`, allowing `curr >= max` to correctly deny excess concurrent transfers.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/mod_xfer.c b/modules/mod_xfer.c
index bcaf72ba7..1730fb84b 100644
--- a/modules/mod_xfer.c
+++ b/modules/mod_xfer.c
@@ -417,7 +417,7 @@ static int xfer_check_limit(cmd_rec *cmd) {
         continue;
       }
 
-      if (strcmp(score->sce_cmd, xfer_cmd) == 0) {
+      if (strcmp(score->sce_cmd, xfer_cmd) != 0) {
         pr_trace_msg(trace_channel, 25,
           "MaxTransfersPerUser: command '%s' does not match '%s', skipping",
           xfer_cmd, score->sce_cmd);
```