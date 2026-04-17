# Bridge token persisted to journal

## Classification
- Type: vulnerability
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasix/port_bridge.rs:37`
- `lib/journal/src/entry.rs:278`
- `lib/journal/src/concrete/archived.rs:780`
- `lib/journal/src/concrete/archived.rs:1458`
- `lib/wasix/src/syscalls/journal/play_event.rs:460`

## Summary
Successful `port_bridge` calls persisted the caller-supplied bridge token into the journal. The token comes from untrusted guest input and was stored as a first-class journal field, making it recoverable by any journal reader and replay path.

## Provenance
- Verified from the supplied reproducer and code inspection
- Reference: https://swival.dev

## Preconditions
- Journaling is enabled
- The caller invokes `port_bridge` with a token
- `port_bridge_internal` succeeds
- The journal is readable by another component, operator, or replay consumer

## Proof
- `port_bridge` reads `token` from guest memory via `get_input_str_ok!` in `lib/wasix/src/syscalls/wasix/port_bridge.rs`
- After success, the journaling path calls `JournalEffector::save_port_bridge(&mut ctx, network, token, security)`, forwarding the raw secret
- The schema stores that value directly: `PortBridgeV1` includes `token: Cow<'a, str>` in `lib/journal/src/entry.rs:278`
- Archived serialization also writes the token in `lib/journal/src/concrete/archived.rs:780` and `lib/journal/src/concrete/archived.rs:1458`
- Replay reads the token back from `JournalEntry::PortBridgeV1 { network, token, security }` in `lib/wasix/src/syscalls/journal/play_event.rs:460` and reuses it, confirming the secret is intentionally persisted and recoverable

## Why This Is A Real Bug
The bridge token is an access secret, not derived state. Persisting it to the journal broadens exposure from the original caller to any actor with journal read access, including replay tooling and storage operators. This creates a clear confidentiality leak on every successful `port_bridge` call under journaling.

## Fix Requirement
Do not persist the bridge token to the journal. Omit the field or replace it with a non-secret redacted placeholder, and update replay handling so it no longer depends on recovering the original token from journaled data.

## Patch Rationale
The patch removes the token from journal persistence and replay semantics, preserving journaling for the operation metadata while preventing secret disclosure. This directly addresses the confidentiality issue at the sink rather than attempting to restrict downstream readers.

## Residual Risk
None

## Patch
- Patch file: `043-bridge-token-persisted-to-journal.patch`
- The patch redacts or removes token persistence from the `port_bridge` journal path
- The patch updates journal schema/serialization and replay handling so journal readers no longer recover the raw bridge token