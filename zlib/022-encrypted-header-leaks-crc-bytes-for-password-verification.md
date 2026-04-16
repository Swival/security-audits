# Encrypted header leaks CRC bytes for password verification

## Classification
Medium severity vulnerability. Confidence: certain.

## Affected Locations
- `contrib/minizip/crypt.h:109`
- `contrib/minizip/crypt.h:57`
- `contrib/minizip/crypt.h:71`
- `contrib/minizip/unzip.c:1488`
- `contrib/minizip/zip.c:1870`
- `contrib/minizip/zip.c:1961`

## Summary
Traditional PKWARE encryption in Minizip embeds the high CRC bytes into the encrypted 12-byte header. Because header decryption depends only on password-derived key state, an attacker with the encrypted archive can verify password guesses offline by decrypting the header and checking those bytes against CRC values available from ZIP metadata.

## Provenance
Verified from repository source and reproduced against the stated code paths. External scanner reference: https://swival.dev

## Preconditions
- Traditional PKWARE ZIP encryption is enabled and used
- The attacker can read the encrypted ZIP archive header
- The attacker can obtain ZIP metadata containing the file CRC, including central directory records

## Proof
`crypthead()` writes CRC-derived bytes into the final encrypted header positions using `zencode(..., (crcForCrypting >> 16) & 0xff, ...)` and `zencode(..., (crcForCrypting >> 24) & 0xff, ...)` at `contrib/minizip/crypt.h:109`. Header decryption during verification uses only password-derived key evolution via `init_keys()` and `zdecode()` at `contrib/minizip/crypt.h:57` and `contrib/minizip/crypt.h:71`, as exercised by header processing in `contrib/minizip/unzip.c:1488`. The expected CRC is stored in archive metadata during writing at `contrib/minizip/zip.c:1870` and patched into the local header at `contrib/minizip/zip.c:1961`. A guessed password is therefore testable offline by decrypting the header and comparing the recovered final two bytes to the known high CRC bytes.

## Why This Is A Real Bug
This creates a practical password-verification oracle for encrypted ZIP files using legacy PKWARE encryption. The check is offline, requires no interaction with a victim, and materially reduces attacker cost for password guessing. Although this behavior is inherent to the legacy format, shipping code that enables it still exposes users to a real and exploitable weakness.

## Fix Requirement
Do not use Traditional PKWARE encryption for new or supported protected archives. Disable this mode or reject it at build/runtime, and require authenticated AES-based ZIP encryption that does not expose CRC-based password checks.

## Patch Rationale
The patch removes acceptance of the legacy PKWARE path and directs callers to stronger ZIP encryption, eliminating the CRC-based header oracle rather than trying to mask a format-level weakness that is fundamental to the scheme.

## Residual Risk
None

## Patch
Patched in `022-encrypted-header-leaks-crc-bytes-for-password-verification.patch`.