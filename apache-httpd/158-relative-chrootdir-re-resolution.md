# Relative ChrootDir Re-Resolution

## Classification

Validation gap, medium severity.

## Affected Locations

`modules/arch/unix/mod_unixd.c:171`

Additional reproduced vulnerable sequence:

`modules/arch/unix/mod_unixd.c:341`

## Summary

`ChrootDir` accepts relative paths during configuration validation. The configured value is then used in a `chdir()` followed by `chroot()` sequence. For a relative value, the second path lookup is resolved after the working directory has changed, so `chroot()` targets a different directory than the one validated.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Server starts as root.
- `ChrootDir` is configured with a relative path, for example `ChrootDir jail`.
- The startup working directory contains `jail/`.
- The validated directory contains a nested same-name directory, for example `jail/jail/`.

## Proof

`unixd_set_chroot_dir()` validates only that the supplied argument is a directory:

```c
if (!ap_is_directory(cmd->pool, arg)) {
    return "ChrootDir must be a valid directory";
}

ap_unixd_config.chroot_dir = arg;
```

For `ChrootDir jail`, validation applies to `./jail`, and the unchanged relative string is stored.

During privilege drop, the stored value is used twice:

```c
chdir(ap_unixd_config.chroot_dir);
chroot(ap_unixd_config.chroot_dir);
```

After `chdir("jail")`, the process working directory is `./jail`. The following `chroot("jail")` resolves relative to that new working directory and therefore targets `./jail/jail`, not the originally validated `./jail`.

The same sequence is present in `ap_unixd_setup_child()`.

Practical trigger:

1. Start as root with `ChrootDir jail`.
2. Ensure the startup cwd contains `jail/`.
3. Ensure `jail/jail/` also exists.
4. The config check validates `./jail`, but the privilege-drop hook chroots into `./jail/jail`.

## Why This Is A Real Bug

The configuration-time validation and runtime use do not refer to the same filesystem object when `ChrootDir` is relative. This can cause the server to enter an unintended chroot root. If the nested directory exists, startup can succeed with the wrong filesystem root. If it does not exist, startup or child initialization fails at `chroot()`.

## Fix Requirement

Reject relative `ChrootDir` values or canonicalize the configured directory before storing and using it for `chroot()`.

## Patch Rationale

The patch rejects non-absolute `ChrootDir` values in `unixd_set_chroot_dir()` before directory validation and storage. This ensures the path validated during configuration is the same path later used by `chdir()` and `chroot()`, regardless of the current working directory.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/arch/unix/mod_unixd.c b/modules/arch/unix/mod_unixd.c
index 1baa278..7cd15d1 100644
--- a/modules/arch/unix/mod_unixd.c
+++ b/modules/arch/unix/mod_unixd.c
@@ -254,6 +254,9 @@ unixd_set_chroot_dir(cmd_parms *cmd, void *dummy,
     if (err != NULL) {
         return err;
     }
+    if (arg[0] != '/') {
+        return "ChrootDir must be an absolute path";
+    }
     if (!ap_is_directory(cmd->pool, arg)) {
         return "ChrootDir must be a valid directory";
     }
```