# WCGI guest bypasses configured thread limits

## Classification
- Type: trust-boundary violation
- Severity: critical
- Confidence: certain

## Affected Locations
- `lib/wasix/src/runners/wcgi/create_env.rs:28`
- `lib/wasix/src/runners/wcgi/create_env.rs:37`

## Summary
`default_create_env` constructs the WCGI guest environment with hard-coded permissive/default capability values instead of preserving trusted server-side limits from `CreateEnvConfig`. In particular, it replaces the configured `threading` capability with `Default::default()`, which results in `None` and removes the administrator-defined thread/task cap for executed guests.

## Provenance
- Verified from local source review and reproduction notes provided with this finding
- Scanner reference: https://swival.dev

## Preconditions
- Attacker can cause a WCGI module to be executed

## Proof
At `lib/wasix/src/runners/wcgi/create_env.rs:28`, request handling reaches `default_create_env`, which rebuilds guest capabilities rather than carrying forward trusted restrictions from `CreateEnvConfig`.
At `lib/wasix/src/runners/wcgi/create_env.rs:37`, the function assigns `threading: Default::default()`.
For this capability type, `Default::default()` is `None`, meaning no thread/task limit is enforced.
Therefore a WCGI guest can spawn more threads/tasks than the server administrator configured, crossing the intended resource-control trust boundary.

## Why This Is A Real Bug
The server-side configuration is the trusted boundary that should constrain untrusted WCGI guests. Dropping the configured `threading` limit during environment creation silently disables that control for attacker-supplied or attacker-triggered modules. This is directly security-relevant because thread/task limits are a host resource safeguard, and bypassing them enables denial-of-service through excess concurrency.

## Fix Requirement
Preserve least-privilege, trusted capability settings when building the WCGI environment. Do not replace configured capability limits with permissive or default values unless explicitly authorized by trusted server configuration.

## Patch Rationale
The patch updates `lib/wasix/src/runners/wcgi/create_env.rs` to stop discarding the configured capability set during WCGI environment creation. In particular, it preserves the incoming `threading` restriction instead of resetting it to `Default::default()`, ensuring the administrator-defined thread/task cap remains effective for the guest.

## Residual Risk
None

## Patch
Patched in `049-wcgi-guest-gets-all-capabilities.patch`.