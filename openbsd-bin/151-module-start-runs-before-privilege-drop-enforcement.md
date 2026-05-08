# module start runs before privilege-drop enforcement

## Classification

Security control failure, high severity. Confidence: certain.

## Affected Locations

`usr.sbin/radiusd/radiusd_module.c:422`

## Summary

`IMSG_RADIUSD_MODULE_START` enforced `base->priv_dropped` only after invoking a module start handler. If `module_drop_privilege()` failed and left the process privileged, any module with `module_start_module != NULL` could execute its start callback as root before the later abort.

## Provenance

Verified from supplied source, reproducer summary, and patch.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The module has a start handler.
- `module_drop_privilege()` failed before setting `base->priv_dropped`.
- A reachable `IMSG_RADIUSD_MODULE_START` message is processed after that failure.

## Proof

In the vulnerable `IMSG_RADIUSD_MODULE_START` case, the code first called:

```c
module_start_module(base->ctx);
```

and only then checked:

```c
if (!base->priv_dropped) {
	syslog(LOG_ERR, "Module tried to start with root privileges");
	abort();
}
```

`module_drop_privilege()` returns through `on_fail` without setting `base->priv_dropped` when `getpwnam`, `chroot`, `chdir`, `setgroups`, `setresgid`, or `setresuid` fails.

The module process still continues into load/run paths, and the parent later sends `IMSG_RADIUSD_MODULE_START` from `radiusd_module_start()` at `usr.sbin/radiusd/radiusd.c:1241`.

Therefore, after a privilege-drop failure, the START handler can execute the module start callback while still privileged. The reproducer confirmed this ordering and identified built-in start handlers, including `module_radius_start()` at `usr.sbin/radiusd/radiusd_radius.c:240`.

## Why This Is A Real Bug

The intended security invariant is that module start code must not run with root privileges after privilege dropping fails. The existing abort did not preserve that invariant because it occurred after callback execution. Any side effects performed by the start callback happened before termination, so the control failed open for modules with start handlers.

## Fix Requirement

Check `base->priv_dropped` and abort before invoking `module_start_module(base->ctx)` or otherwise starting the module.

## Patch Rationale

The patch moves the privilege-drop enforcement to the beginning of the `IMSG_RADIUSD_MODULE_START` case. This makes the privileged state check unconditional and shared by both branches:

- If `base->priv_dropped` is false, the process logs and aborts immediately.
- If privileges were dropped, modules with start handlers run normally.
- If no start handler exists, the module sends `IMSG_OK` as before.

This preserves existing behavior for valid states while preventing any START callback from executing before enforcement.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/radiusd/radiusd_module.c b/usr.sbin/radiusd/radiusd_module.c
index 0c1a09d..efda1d2 100644
--- a/usr.sbin/radiusd/radiusd_module.c
+++ b/usr.sbin/radiusd/radiusd_module.c
@@ -427,21 +427,15 @@ module_imsg_handler(struct module_base *base, struct imsg *imsg)
 		break;
 	    }
 	case IMSG_RADIUSD_MODULE_START:
-		if (module_start_module != NULL) {
-			module_start_module(base->ctx);
-			if (!base->priv_dropped) {
-				syslog(LOG_ERR, "Module tried to start with "
-				    "root privileges");
-				abort();
-			}
-		} else {
-			if (!base->priv_dropped) {
-				syslog(LOG_ERR, "Module tried to start with "
-				    "root privileges");
-				abort();
-			}
-			module_send_message(base, IMSG_OK, NULL);
+		if (!base->priv_dropped) {
+			syslog(LOG_ERR, "Module tried to start with "
+			    "root privileges");
+			abort();
 		}
+		if (module_start_module != NULL)
+			module_start_module(base->ctx);
+		else
+			module_send_message(base, IMSG_OK, NULL);
 		break;
 	case IMSG_RADIUSD_MODULE_STOP:
 		module_stop(base);
```