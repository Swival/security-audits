# Missing Conflict Dependency Unrefs Null Package

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.bin/pkgconf/libpkgconf/pkg.c:1699`

## Summary

An attacker-controlled `.pc` file can crash `pkgconf` during dependency traversal by declaring the same unavailable package in both `Requires` and `Conflicts`. The conflicts walker calls `pkgconf_pkg_unref()` on a `NULL` package pointer returned by failed dependency resolution, causing a null pointer dereference and process termination.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The victim resolves a package containing attacker-controlled `Requires` and `Conflicts` fields.
- The `Conflicts` entry matches a `Requires` entry by package name.
- The matching package is unavailable in the configured pkg-config search path.

## Proof

A reproducing `.pc` file:

```pkgconfig
Name: victim
Description: repro
Version: 1
Requires: missingdep
Conflicts: missingdep
```

Running:

```sh
PKG_CONFIG_LIBDIR=/tmp/pkgconf-repro/pc /tmp/pkgconf-repro-build/pkg-config --exists victim
```

terminated with:

```text
Segmentation fault: 11
exit code 139
```

A control run with `--ignore-conflicts` exited normally with status `1`, confirming the crash is in the conflicts path.

The failing path is:

- `pkgconf_pkg_parser_keyword_set()` parses `Requires` into `pkg->required` and `Conflicts` into `pkg->conflicts`.
- `pkgconf_pkg_walk_conflicts_list()` compares each conflict name against `root->required`.
- For a matching unavailable package, `pkgconf_pkg_verify_dependency()` returns `NULL` and sets `PACKAGE_NOT_FOUND`.
- The non-OK branch still calls `pkgconf_pkg_unref(client, pkgdep)` with `pkgdep == NULL`.
- `pkgconf_pkg_unref()` immediately dereferences `pkg->owner`, crashing the process.

## Why This Is A Real Bug

The dependency verifier explicitly uses `NULL` as the failure result for unsatisfied dependencies. Other traversal code handles this possibility before unrefing. The conflicts traversal did not, so a valid error path becomes a process crash. Because `.pc` metadata can be supplied by packages or build inputs, an attacker-controlled package metadata file can reliably terminate consumers that resolve it.

## Fix Requirement

Only call `pkgconf_pkg_unref(client, pkgdep)` when `pkgdep` is non-`NULL`.

## Patch Rationale

The patch preserves existing conflict-resolution behavior while making the cleanup path match the ownership contract: unref only valid package references. When dependency verification fails and returns `NULL`, there is no acquired package reference to release.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/pkgconf/libpkgconf/pkg.c b/usr.bin/pkgconf/libpkgconf/pkg.c
index a8c1f26..085ef79 100644
--- a/usr.bin/pkgconf/libpkgconf/pkg.c
+++ b/usr.bin/pkgconf/libpkgconf/pkg.c
@@ -1666,7 +1666,8 @@ pkgconf_pkg_walk_conflicts_list(pkgconf_client_t *client,
 				return PKGCONF_PKG_ERRF_PACKAGE_CONFLICT;
 			}
 
-			pkgconf_pkg_unref(client, pkgdep);
+			if (pkgdep != NULL)
+				pkgconf_pkg_unref(client, pkgdep);
 		}
 	}
```