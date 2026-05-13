# odd-length shasum panics parser

## Classification

Denial of service, medium severity, confidence certain.

## Affected Locations

`src/install/integrity.rs:82`

## Summary

`Integrity::parse_sha_sum` parses SHA1 `shasum` metadata two hex nibbles at a time, but previously only checked `i < end` before reading the first nibble. For odd-length inputs below 40 bytes, the parser read the final dangling high nibble, incremented `i`, then indexed `buf[i]` for the missing low nibble, causing a Rust bounds-check panic. Because npm registry metadata can provide `dist.shasum`, a malicious registry response can abort installation.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The installer parses attacker-controlled SHA1 `shasum` metadata.
- The attacker can supply a `dist.shasum` value through registry metadata.
- The supplied value has an odd length below the 40-character SHA1 hex length cap and valid hex before the dangling nibble, for example `0`.

## Proof

`src/install/integrity.rs` computes:

```rust
let end: usize = b"3cd0599b099384b815c10f7fa7df0092b62d534f"
    .len()
    .min(buf.len());
```

The loop then consumes two bytes per iteration:

```rust
while i < end {
    let x0 = bun_core::fmt::hex_digit_value(buf[i])
        .ok_or_else(|| bun_core::err!("InvalidCharacter"))?;
    i += 1;
    let x1 = bun_core::fmt::hex_digit_value(buf[i])
        .ok_or_else(|| bun_core::err!("InvalidCharacter"))?;
```

For input `b"0"`:

- `end == 1`.
- `while i < end` is true for `i == 0`.
- `buf[0]` is read successfully as the high nibble.
- `i` is incremented to `1`.
- `buf[1]` is read for the low nibble and panics because the slice length is `1`.

Reachability is source-grounded: `src/install/npm.rs:2722` reads `dist.shasum` from registry metadata, and `src/install/npm.rs:2725` calls `Integrity::parse_sha_sum(shasum_str).unwrap_or_default()`. `unwrap_or_default()` handles returned errors, but it does not catch panics.

## Why This Is A Real Bug

The parser accepts an arbitrary byte slice from package metadata and performs an unchecked second index operation within the loop. Rust bounds checks convert that out-of-bounds read into a panic. The workspace configures aborting panic behavior in `Cargo.toml:151` and `Cargo.toml:154`, so the panic aborts the installer process rather than returning an integrity parse failure. This creates a practical denial of service against installs using attacker-controlled registry metadata.

The exploitable class is narrower than all odd lengths: odd lengths greater than 40 are truncated to `end == 40` and do not trigger this specific out-of-bounds read. Odd lengths below 40 with valid hex through the dangling final nibble do trigger it.

## Fix Requirement

Reject an odd effective parse length before entering the two-nibble parsing loop, or otherwise guarantee `i + 1 < end` before reading the low nibble. Invalid malformed shasums must be returned as an error, not allowed to panic.

## Patch Rationale

The patch adds an explicit parity check after computing the effective parse length:

```rust
if end % 2 != 0 {
    return Err(bun_core::err!("InvalidCharacter"));
}
```

This preserves the existing 40-character cap while ensuring the loop always has a complete high/low hex pair for every iteration. Malformed odd-length shasums now follow the existing error path, allowing callers such as `unwrap_or_default()` to recover without aborting the process.

## Residual Risk

None

## Patch

```diff
diff --git a/src/install/integrity.rs b/src/install/integrity.rs
index a98876c991..32cce5a563 100644
--- a/src/install/integrity.rs
+++ b/src/install/integrity.rs
@@ -65,6 +65,9 @@ impl Integrity {
         let end: usize = b"3cd0599b099384b815c10f7fa7df0092b62d534f"
             .len()
             .min(buf.len());
+        if end % 2 != 0 {
+            return Err(bun_core::err!("InvalidCharacter"));
+        }
         let mut out_i: usize = 0;
         let mut i: usize = 0;
```