# Unbounded Bcrypt Cost Enables Verification DoS

## Classification

Denial of service, medium severity.

## Affected Locations

- `lib/std/crypto/bcrypt.zig:780`
- Patched code path: `CryptFormatHasher.verify()`

## Summary

`strVerify()` dispatches any hash string beginning with `"$2"` to modular crypt bcrypt verification. The verifier parsed the two-character bcrypt cost as `u6`, allowing values up to `63`, then used that value as `rounds_log` for bcrypt recomputation. A crafted hash such as `"$2b$63$..."` therefore caused verification to attempt `2^63` bcrypt expansion iterations before returning failure, enabling CPU exhaustion when applications verify backend-supplied hash strings.

## Provenance

Verified and reproduced from a Swival.dev Security Scanner finding.

Scanner URL: https://swival.dev

Confidence: certain.

## Preconditions

- An application calls `strVerify()` on bcrypt hash strings supplied by, stored in, or modifiable through an untrusted backend, file, database, or equivalent storage layer.
- The attacker can cause a syntactically valid modular crypt bcrypt string with an excessive cost, e.g. cost `63`, to be verified.

## Proof

The vulnerable path is:

1. `strVerify()` checks `mem.startsWith(u8, str, crypt_format.prefix)`, where the prefix is `"$2"`.
2. Matching strings are dispatched to `CryptFormatHasher.verify()`.
3. `CryptFormatHasher.verify()` validates only length and separator positions:
   - `str.len == 60`
   - `str[3] == '$'`
   - `str[6] == '$'`
4. It parses the cost with:

   ```zig
   const rounds_log = fmt.parseInt(u6, rounds_log_str[0..], 10) catch
       return HasherError.InvalidEncoding;
   ```

   `u6` permits values from `0` through `63`.

5. The parsed value is passed into:

   ```zig
   crypt_format.strHashInternal(password, &salt, .{
       .rounds_log = rounds_log,
       .silently_truncate_password = silently_truncate_password,
   });
   ```

6. `strHashInternal()` calls `bcrypt()`, which calls `bcryptWithTruncation()`.
7. `bcryptWithTruncation()` computes:

   ```zig
   const rounds: u64 = @as(u64, 1) << params.rounds_log;
   var k: u64 = 0;
   while (k < rounds) : (k += 1) {
       state.expand0(passwordZ);
       state.expand0(salt);
   }
   ```

A modular crypt bcrypt string shaped like:

```text
$2b$63$<22 valid bcrypt-base64 salt chars><31 trailing chars>
```

is accepted far enough to compute `rounds = 1 << 63` and enter the bcrypt expansion loop. The supplied final hash does not need to match; the expensive recomputation occurs before comparison and before `PasswordVerificationFailed` can be returned.

## Why This Is A Real Bug

Bcrypt cost is attacker-controlled in the verification input. Verification must parse stored hash parameters, but it must not allow unbounded or implementation-unsafe work factors. The implementation accepted cost `63`, which maps directly to `2^63` bcrypt expansion iterations. This is effectively non-terminating for a request path and can exhaust CPU or worker threads with a single crafted verification attempt.

The issue is especially relevant where password hashes are read from a database, identity backend, migration file, tenant-controlled storage, or any other source not fully trusted by the verifier.

## Fix Requirement

Reject bcrypt costs outside a safe supported range before invoking bcrypt recomputation.

The check must occur after parsing the cost and before calling `crypt_format.strHashInternal()` / `bcrypt()`.

## Patch Rationale

The patch adds explicit bounds validation in `CryptFormatHasher.verify()`:

```zig
if (rounds_log < 4 or rounds_log > 31) return HasherError.InvalidEncoding;
```

This prevents pathological values such as `63` from reaching `bcryptWithTruncation()`. Returning `InvalidEncoding` is appropriate because the encoded hash requests an unsupported bcrypt cost.

The upper bound prevents impossible or denial-of-service-grade computations. The lower bound rejects invalid/unsupported weak bcrypt costs in the modular crypt verifier.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/bcrypt.zig b/lib/std/crypto/bcrypt.zig
index 55d00c1d27..27eeab920b 100644
--- a/lib/std/crypto/bcrypt.zig
+++ b/lib/std/crypto/bcrypt.zig
@@ -755,6 +755,7 @@ const CryptFormatHasher = struct {
         const rounds_log_str = str[4..][0..2];
         const rounds_log = fmt.parseInt(u6, rounds_log_str[0..], 10) catch
             return HasherError.InvalidEncoding;
+        if (rounds_log < 4 or rounds_log > 31) return HasherError.InvalidEncoding;
 
         const salt_str = str[7..][0..salt_str_length];
         var salt: [salt_length]u8 = undefined;
```
