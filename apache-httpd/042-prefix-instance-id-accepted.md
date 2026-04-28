# Prefix Instance ID Accepted

## Classification

Authorization flaw, medium severity.

## Affected Locations

`server/mpm/netware/mpm_netware.c:1223`

## Summary

The NetWare console command handler accepted `-p` instance selectors by prefix. If one NetWare instance ID was a prefix of another, commands intended for the longer ID could be handled by the shorter-ID instance.

## Provenance

Verified by reproduced analysis and patched from scanner finding.

Source: Swival Security Scanner, https://swival.dev

## Preconditions

Multiple NetWare instances have IDs where one ID prefixes another, for example `OS` and `OS2`.

## Proof

`CommandLineInterpreter()` receives console input as `commandLine` and copies it into `szcommandLine`.

The handler locates an instance selector with:

```c
pID = strstr(szcommandLine, "-p");
```

If present, `pID` is advanced past `-p` and spaces are skipped. The affected check then compared only the length of the current instance ID:

```c
strnicmp(pID, ap_my_addrspace, strlen(ap_my_addrspace))
```

For `pID = "OS2"` and `ap_my_addrspace = "OS"`, the comparison length is `2`, so the check succeeds even though the selector token is `OS2`.

After this prefix match, the instance handles commands such as `RESTART`, `SHUTDOWN`, `SETTINGS`, `MODULES`, `DIRECTIVES`, and `VERSION`.

## Why This Is A Real Bug

The `-p` argument is an instance authorization/routing selector. Treating it as a prefix violates the expected invariant that a command is handled only by the exact selected instance.

With prefix-related IDs, availability-affecting commands such as `SHUTDOWN` and `RESTART` can be executed by the wrong instance.

## Fix Requirement

Compare the complete `-p` instance token. After matching `ap_my_addrspace`, require the next character to be whitespace or the string terminator.

## Patch Rationale

The patch preserves the existing case-insensitive comparison, then adds a token-boundary check:

```c
(pID[strlen(ap_my_addrspace)] &&
 !apr_isspace(pID[strlen(ap_my_addrspace)]))
```

This rejects longer tokens that merely start with the current instance ID, while still accepting exact matches followed by whitespace or end-of-string.

## Residual Risk

None

## Patch

```diff
diff --git a/server/mpm/netware/mpm_netware.c b/server/mpm/netware/mpm_netware.c
index e89fdef..7648723 100644
--- a/server/mpm/netware/mpm_netware.c
+++ b/server/mpm/netware/mpm_netware.c
@@ -1211,7 +1211,10 @@ static int CommandLineInterpreter(scr_t screenID, const char *commandLine)
             while (*pID && (*pID == ' '))
                 pID++;
         }
-        if (pID && ap_my_addrspace && strnicmp(pID, ap_my_addrspace, strlen(ap_my_addrspace)))
+        if (pID && ap_my_addrspace &&
+            (strnicmp(pID, ap_my_addrspace, strlen(ap_my_addrspace)) ||
+             (pID[strlen(ap_my_addrspace)] &&
+              !apr_isspace(pID[strlen(ap_my_addrspace)]))))
             return NOTMYCOMMAND;
 
         /* If we have determined that this command belongs to this
```