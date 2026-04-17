# TLS 1.2 receive path suppresses decryption errors

## Classification
- Type: error-handling bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/picotls.c:2906`

## Summary
`handle_input_tls12` records fatal TLS 1.2 receive-side failures such as nonce decode errors, truncated records, AEAD/MAC failures, invalid alerts, and unexpected content types, but unconditionally returns `0` at `lib/picotls.c:2906`. When reached through `ptls_receive`, this converts authenticated decryption and parse failures into apparent success, preventing callers from detecting corrupted unauthenticated records on the imported TLS 1.2 post-handshake receive path.

## Provenance
- Verified from reproduced behavior and source analysis in the local worktree
- Scanner origin: [Swival Security Scanner](https://swival.dev)

## Preconditions
- Imported or resumed TLS 1.2 connection receives a malformed encrypted record
- Execution reaches the TLS 1.2 receive path with `dec.tls12` set

## Proof
- `ptls_receive` dispatches to `handle_input_tls12` when TLS 1.2 decryption state is active.
- Inside `handle_input_tls12`, decryption and parsing failures set `ret` to fatal values including bad record MAC and decode errors.
- At `lib/picotls.c:2906`, the function returns `0` instead of `ret`.
- `ptls_receive` therefore enters its success handling path at `lib/picotls.c:6101`, consuming the record without surfacing the failure.
- Reproduction with public APIs confirmed:
  - valid TLS 1.2 application record: `ret=0`, plaintext decrypted
  - same record with one flipped ciphertext/tag bit: `ret=0`, full record consumed, `plaintext_len=0`
- This matches the source path: authentication failure sets `ret = PTLS_ALERT_BAD_RECORD_MAC`, then that value is discarded before returning.

## Why This Is A Real Bug
Suppressing TLS record authentication and decode failures violates the expected contract of the receive API and can cause callers to treat corrupted or unauthenticated traffic as successfully processed. The behavior is directly reachable on the supported imported TLS 1.2 post-handshake receive path, was reproduced with public APIs, and is not a theoretical inconsistency.

## Fix Requirement
Return the actual `ret` value from `handle_input_tls12` so fatal TLS 1.2 decryption and parsing errors propagate back to `ptls_receive` and its callers.

## Patch Rationale
The minimal safe fix is to replace the unconditional success return with `return ret;` in `handle_input_tls12`. This preserves existing successful behavior while restoring error propagation for all already-detected fatal conditions, including MAC/authentication failures and malformed record handling.

## Residual Risk
None

## Patch
- Patch file: `001-tls-1-2-receive-path-suppresses-decryption-errors.patch`
- Change: replace the unconditional `return 0;` in `handle_input_tls12` with `return ret;`
- Effect: TLS 1.2 imported post-handshake receive errors now propagate to `ptls_receive` callers instead of being silently suppressed