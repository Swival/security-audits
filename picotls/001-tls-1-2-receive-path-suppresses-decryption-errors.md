# TLS 1.2 receive path drops fatal decrypt failures

## Classification
- Type: error-handling bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/picotls.c:2906`

## Summary
`handle_input_tls12` records fatal TLS 1.2 receive errors such as nonce decode failure, truncated record, AEAD/MAC failure, malformed alert, and unexpected record type, but returns `0` instead of the accumulated error code. This causes `ptls_receive` to treat corrupted imported/resumed TLS 1.2 post-handshake records as successful input processing.

## Provenance
- Verified by reproduction against the affected code path and patched locally in `001-tls-1-2-receive-path-suppresses-decryption-errors.patch`
- Scanner source: [Swival Security Scanner](https://swival.dev)

## Preconditions
- Imported or resumed TLS 1.2 connection
- Post-handshake encrypted record is received
- The record is malformed, truncated, fails authentication, or decodes to an invalid TLS record state

## Proof
- `ptls_receive` dispatches to `handle_input_tls12` when `tls->traffic_protection.dec.tls12` is active.
- Inside `handle_input_tls12`, fatal conditions set `ret` to an error, including `PTLS_ALERT_BAD_RECORD_MAC`.
- At `lib/picotls.c:2906`, the function returns `0` unconditionally rather than returning `ret`.
- In `ptls_receive`, the `case 0` success arm is then taken at `lib/picotls.c:6101`, so callers cannot observe the decryption or parse failure.
- Reproduced with a PoC using `ptls_build_tls12_export_params`, `ptls_import`, `ptls_send`, and `ptls_receive`:
  - valid TLS 1.2 application record: `ret=0`, plaintext recovered
  - same record with one ciphertext/tag bit flipped: `ret=0`, full record consumed, `plaintext_len=0`
- This runtime behavior matches the source path: authentication fails, `ret` is set, and the error is discarded before returning.

## Why This Is A Real Bug
The affected path handles authenticated encrypted TLS 1.2 records. Suppressing MAC/decryption and record parsing failures breaks the contract of `ptls_receive`, causes callers to treat invalid input as successfully processed, and can desynchronize connection state while concealing integrity failures. The issue is reachable on the supported imported TLS 1.2 post-handshake receive path and was confirmed both statically and with a runtime reproducer.

## Fix Requirement
Return the actual `ret` value from `handle_input_tls12` so fatal TLS 1.2 receive errors propagate to `ptls_receive` and then to the caller.

## Patch Rationale
The patch is minimal and directly restores intended error propagation by replacing the unconditional success return with `return ret;` in `handle_input_tls12`. This preserves existing success behavior while ensuring authenticated decryption and parse failures remain fatal and observable.

## Residual Risk
None

## Patch
- Patched in `001-tls-1-2-receive-path-suppresses-decryption-errors.patch`
- Change: `lib/picotls.c:2906` now returns `ret` instead of unconditional success