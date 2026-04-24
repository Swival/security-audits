# Multiple PEM private keys are silently accepted in client certificate config

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/config/backends/client_cert_info.rs:106`

## Summary
Config parsing for backend client certificates accepts `key` and `key_file` inputs that contain multiple PEM private keys. The parser returns the first supported private key it encounters and ignores any later private keys, instead of rejecting malformed multi-key input. This creates inconsistent behavior with the direct constructor path, which already rejects more than one private key.

## Provenance
- Verified from the provided reproducer and source inspection
- Swival Security Scanner: https://swival.dev

## Preconditions
- Client certificate configuration provides a `key` or `key_file` value containing more than one PEM-encoded private key

## Proof
- `TryFrom<toml::Value>` for client certificate config routes `key` and `key_file` through `read_key` in `src/config/backends/client_cert_info.rs:106`
- The original `read_key` implementation iterates over `rustls_pemfile::read_all(reader)?` and returns immediately when it sees the first `RSAKey`, `PKCS8Key`, or `ECKey`
- Because it exits early, it never validates whether additional private keys exist later in the same PEM input
- The direct constructor path already enforces single-key semantics by erroring when `keys.len() > 1`, so config-driven parsing is observably inconsistent
- The reproducer confirmed runtime reachability by concatenating `test-fixtures/data/client.key` twice into a single `key_file` and parsing with `viceroy_lib::config::FastlyConfig::from_str`, which succeeded and used the first key

## Why This Is A Real Bug
The bug is not theoretical: malformed multi-key input is accepted during normal config parsing, and the resulting `ClientCertInfo` is consumed by TLS setup through `with_client_auth_cert(certed_key.certs(), certed_key.key())` in `src/upstream.rs:166`. That means the application proceeds with a silently truncated interpretation of security-sensitive configuration. Silent acceptance of ambiguous key material is a real validation failure and contradicts existing single-key expectations elsewhere in the same component.

## Fix Requirement
Update `read_key` to collect private-key entries from PEM input and return an error unless exactly one supported private key is present.

## Patch Rationale
The patch aligns file-backed and inline config parsing with the existing constructor invariant: exactly one private key must be supplied. By scanning the full PEM input before deciding, the parser now rejects multi-key input instead of silently discarding trailing keys. This removes the inconsistency and makes malformed configuration fail closed.

## Residual Risk
None

## Patch
- Patch file: `028-multiple-keys-in-file-or-inline-key-input-are-silently-accep.patch`
- Change: `src/config/backends/client_cert_info.rs` now collects supported PEM private keys while parsing and errors unless the count is exactly one
- Effect: both `key` and `key_file` reject PEM input containing zero or multiple private keys, matching the stricter constructor behavior