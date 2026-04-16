# GeneralizedTime Accepts Missing Z Terminator

## Classification

- Type: security control failure
- Severity: High
- Confidence: Certain

## Affected Locations

- `lib/std/crypto/Certificate.zig:603`
- Function: `parseTime`
- Branch: `.generalized_time`

## Summary

The X.509 certificate validity parser accepted malformed DER `GeneralizedTime` values that did not end with the required `Z` UTC terminator.

`UTCTime` validation required an exact length and `Z` suffix, but `GeneralizedTime` only required `bytes.len >= 15` and parsed the first 14 digits. A value such as `19920521000000X` was accepted and converted to a normal timestamp.

Because parsed validity timestamps are later used directly by certificate verification, an attacker-supplied certificate with an invalid lifetime encoding could pass the validity-time security control.

## Provenance

- Source: Swival.dev Security Scanner
- Scanner URL: https://swival.dev
- Finding: `GeneralizedTime accepts missing Z terminator`
- Reproduction status: Reproduced
- Patch: `035-generalizedtime-accepts-missing-z-terminator.patch`

## Preconditions

- A caller parses or verifies an attacker-supplied certificate.

## Proof

The vulnerable parser logic was:

```zig
.generalized_time => {
    // Examples:
    // "19920521000000Z"
    // "19920622123421Z"
    // "19920722132100.3Z"
    if (bytes.len < 15)
        return error.CertificateTimeInvalid;
    return Date.toSeconds(.{
        .year = try parseYear4(bytes[0..4]),
        .month = try parseTimeDigits(bytes[4..6], 1, 12),
        .day = try parseTimeDigits(bytes[6..8], 1, 31),
        .hour = try parseTimeDigits(bytes[8..10], 0, 23),
        .minute = try parseTimeDigits(bytes[10..12], 0, 59),
        .second = try parseTimeDigits(bytes[12..14], 0, 59),
    });
},
```

This accepted any `GeneralizedTime` with at least 15 bytes, without checking that byte 14 was `Z`.

Example accepted malformed value:

```text
19920521000000X
```

The parser read:

- year: `1992`
- month: `05`
- day: `21`
- hour: `00`
- minute: `00`
- second: `00`

It ignored that the terminator was `X`, not `Z`.

The parsed timestamp was stored in:

```zig
.validity = .{
    .not_before = not_before_utc,
    .not_after = not_after_utc,
},
```

Verification later only compared timestamps:

```zig
if (now_sec < parsed_subject.validity.not_before)
    return error.CertificateNotYetValid;
if (now_sec > parsed_subject.validity.not_after)
    return error.CertificateExpired;
```

It did not retain or revalidate the original DER time encoding.

## Why This Is A Real Bug

X.509 certificate validity times are part of certificate verification. The parser is expected to reject malformed validity encodings.

The `UTCTime` branch already enforced both exact length and `Z` termination:

```zig
if (bytes.len != 13)
    return error.CertificateTimeInvalid;
if (bytes[12] != 'Z')
    return error.CertificateTimeInvalid;
```

The `GeneralizedTime` branch failed to enforce equivalent grammar for the supported format. As a result, a malformed attacker-controlled certificate validity field could be normalized into a valid timestamp and accepted by the certificate verification path.

Reachability is practical because TLS client certificate processing parses peer-supplied certificate bytes and then verifies the resulting parsed certificate chain.

## Fix Requirement

Validate the supported `GeneralizedTime` grammar before converting it to seconds.

At minimum, for the currently supported non-fractional form, require:

- exact length of 15 bytes
- byte 14 equal to `Z`
- existing digit and range validation for `YYYYMMDDHHMMSS`

## Patch Rationale

The patch changes the `GeneralizedTime` validation from permissive minimum-length parsing to strict validation of the supported encoding form.

Before:

```zig
if (bytes.len < 15)
    return error.CertificateTimeInvalid;
```

After:

```zig
if (bytes.len != 15)
    return error.CertificateTimeInvalid;
if (bytes[14] != 'Z')
    return error.CertificateTimeInvalid;
```

This prevents malformed values such as `19920521000000X` and also prevents trailing garbage after a valid timestamp.

The parser comments mention fractional seconds, but the implementation does not parse fractional seconds. Requiring exactly `YYYYMMDDHHMMSSZ` matches the actual supported parser behavior and avoids accepting encodings it does not fully validate.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/Certificate.zig b/lib/std/crypto/Certificate.zig
index 4defc2a408..34062a12cc 100644
--- a/lib/std/crypto/Certificate.zig
+++ b/lib/std/crypto/Certificate.zig
@@ -596,7 +596,9 @@ pub fn parseTime(cert: Certificate, elem: der.Element) ParseTimeError!u64 {
             // "19920521000000Z"
             // "19920622123421Z"
             // "19920722132100.3Z"
-            if (bytes.len < 15)
+            if (bytes.len != 15)
+                return error.CertificateTimeInvalid;
+            if (bytes[14] != 'Z')
                 return error.CertificateTimeInvalid;
             return Date.toSeconds(.{
                 .year = try parseYear4(bytes[0..4]),
```