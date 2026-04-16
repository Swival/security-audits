# Unqualified `ZLIB1.dll` import crosses library-loading trust boundary

## Classification
- Type: trust-boundary violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `contrib/dotzlib/DotZLib/DotZLib.cs:181`
- `contrib/dotzlib/DotZLib/Deflater.cs:21`
- `contrib/dotzlib/DotZLib/Inflater.cs:21`
- `contrib/dotzlib/DotZLib/GZipStream.cs:20`
- `contrib/dotzlib/DotZLib/ChecksumImpl.cs:108`

## Summary
`DotZLib` imported `ZLIB1.dll` by bare filename in multiple `[DllImport]` declarations. Reaching `new Info()`, `Info.Version`, compression, decompression, gzip, or checksum paths caused the CLR to resolve `ZLIB1.dll` through normal process DLL search rules. Under the stated precondition, this allowed a planted attacker-controlled `ZLIB1.dll` from a writable search-path location to be loaded and executed in-process instead of the intended zlib binary.

## Provenance
- Verified from the supplied finding and reproducer
- Source reviewed in the affected files listed above
- Scanner source: https://swival.dev

## Preconditions
- The process can resolve native DLLs from an attacker-writable search-path location before the intended zlib library.

## Proof
- `contrib/dotzlib/DotZLib/DotZLib.cs:181` declared native imports as `[DllImport("ZLIB1.dll")]` for `zlibCompileFlags` and `zlibVersion`.
- The same unqualified import pattern existed in `contrib/dotzlib/DotZLib/Deflater.cs:21`, `contrib/dotzlib/DotZLib/Inflater.cs:21`, `contrib/dotzlib/DotZLib/GZipStream.cs:20`, and `contrib/dotzlib/DotZLib/ChecksumImpl.cs:108`.
- `contrib/dotzlib/DotZLib/UnitTests.cs:158` and `contrib/dotzlib/DotZLib/UnitTests.cs:159` show `Info` paths are expected to execute.
- With DLL search order influenced as described, placing a fake `ZLIB1.dll` that exports `zlibCompileFlags` and `zlibVersion` causes that binary to load when `new Info()` or `Info.Version` is reached.
- This reproduces code execution in the host process through unintended native library binding.

## Why This Is A Real Bug
This is not a theoretical naming issue. A bare-name `DllImport` delegates trust to ambient process library search paths, which can include writable locations in real deployments. When that happens, managed code crosses into whichever native binary is resolved first, with the privileges of the host process. The affected entrypoints are reachable by intended product code and tests, so exploitation requires only the documented precondition and normal feature use.

## Fix Requirement
Replace bare-name native imports with explicit trusted library resolution or otherwise constrain loading so `DotZLib` does not bind through attacker-influenced search paths.

## Patch Rationale
The patch centralizes zlib binding behind explicit native DLL resolution and updates all `DotZLib` call sites to use that restricted path instead of `[DllImport("ZLIB1.dll")]`. This removes reliance on default DLL search order and keeps all existing zlib-backed functionality bound to the intended library source.

## Residual Risk
None

## Patch
- Patch file: `015-unqualified-zlib1-dll-import-crosses-library-loading-trust-b.patch`
- The patch replaces unqualified `ZLIB1.dll` imports across `DotZLib` with restricted native library resolution to prevent loading from attacker-controlled search-path locations.