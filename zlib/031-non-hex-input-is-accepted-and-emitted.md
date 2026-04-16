# Non-hex input is accepted and emitted

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `contrib/puff/bin-writer.c:18`

## Summary
`contrib/puff/bin-writer.c` reads two stdin characters into a byte buffer and converts them with `strtol(..., 16)`, but never verifies that both characters were consumed. As a result, malformed pairs such as `4G`, `G4`, and `zz` are accepted and emitted as bytes instead of being rejected.

## Provenance
- Verified from the provided reproducer and source inspection in `contrib/puff/bin-writer.c`
- Scanner origin: https://swival.dev

## Preconditions
- `stdin` contains a non-hex character in a byte pair

## Proof
- `hexStr[0]` and `hexStr[1]` are filled directly from `getchar()` in `contrib/puff/bin-writer.c`
- The pair is parsed with `strtol(hexStr, &endptr, 16)`
- `endptr` is not checked before `fwrite`, so partial parses and zero-length parses still produce output bytes
- Reproduced behavior:
```text
printf '4G ' | /tmp/bin-writer | od -An -t x1  -> 04
printf 'G4 ' | /tmp/bin-writer | od -An -t x1  -> 00
printf 'zz ' | /tmp/bin-writer | od -An -t x1  -> 00
```

## Why This Is A Real Bug
The code path is directly reachable from malformed stdin and deterministically emits bytes derived from invalid text. This silently corrupts the produced binary stream rather than rejecting bad input, which is a concrete input-validation failure with observable output impact.

## Fix Requirement
Reject a parsed pair unless `endptr == hexStr + 2` before writing the byte.

## Patch Rationale
The patch adds strict post-parse validation so output is written only when both input characters are valid hexadecimal digits. This matches the intended byte-pair format and prevents partial or empty conversions from being emitted.

## Residual Risk
None

## Patch
- Patch file: `031-non-hex-input-is-accepted-and-emitted.patch`
- Change: validate full two-character consumption from `strtol` before calling `fwrite` in `contrib/puff/bin-writer.c`