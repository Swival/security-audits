# Build script ignores failures from executed system commands

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `os400/make.sh:92`
- `os400/make.sh:280`
- `os400/make.sh:294`
- `os400/make.sh:310`
- `os400/make.sh:313`
- `os400/make.sh:353`
- `os400/make.sh:354`
- `os400/make.sh:365`
- `os400/make.sh:379`
- `os400/make.sh:382`

## Summary
The build script executes OS/400 build commands via `system "${CMD}"` but does not stop on failure. As a result, failed object creation or link steps are treated as success, and later packaging, binding-directory, and backup steps run against missing or stale artifacts.

## Provenance
- Verified finding reproduced from the supplied report and reproducer summary.
- Reference: https://swival.dev

## Preconditions
- Any invoked `system` command fails during build.

## Proof
At `os400/make.sh:92`, the script invokes `system "${CMD}"` without checking its exit status and without enabling fail-fast shell behavior.

This missing check is security-relevant in reachable paths:
- `os400/make.sh:280` and `os400/make.sh:294` run module build commands without validating success.
- `os400/make.sh:310` and `os400/make.sh:313` rebuild and repopulate the static binding directory for every entry in `MODULES`, including modules whose earlier `CRTCMOD` failed.
- `os400/make.sh:353` executes `CRTSRVPGM`, then `os400/make.sh:354` sets `LINK=YES` unconditionally.
- With that bad state, backup duplication still runs at `os400/make.sh:365`, and dynamic binding directory updates still run at `os400/make.sh:379` and `os400/make.sh:382`.

A failing `CRTCMOD` or `CRTSRVPGM` therefore leaves the script continuing under false success assumptions, producing partial or inconsistent build output.

## Why This Is A Real Bug
This is not a hypothetical hygiene issue. The script mutates build-state flags and performs follow-on build operations after unchecked command failures. That behavior can:
- mark a failed link as successful,
- republish stale objects from prior builds,
- populate binding directories with non-existent modules, and
- complete the build with inconsistent artifacts while hiding the original failure.

That is a concrete error-handling flaw because the script’s control flow no longer reflects the success of the underlying OS/400 toolchain commands.

## Fix Requirement
The script must fail fast on OS/400 command execution errors, either by enabling strict shell failure handling where effective or by checking each `system` invocation result and exiting before any dependent build step runs.

## Patch Rationale
The patch in `027-build-script-ignores-failures-from-executed-system-commands.patch` enforces immediate failure handling for executed system commands so later build stages cannot proceed after `CRTLIB`, `CPY`, `CRTCMOD`, `CRTSRVPGM`, or related command failures. This directly closes the reproduced control-flow gap and prevents false-success state transitions such as unconditional `LINK=YES`.

## Residual Risk
None

## Patch
```diff
diff --git a/os400/make.sh b/os400/make.sh
--- a/os400/make.sh
+++ b/os400/make.sh
@@
-system "${CMD}"
+system "${CMD}" || exit 1
```