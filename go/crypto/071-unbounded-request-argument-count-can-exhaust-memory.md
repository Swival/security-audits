# Unbounded ACVP argument count causes wrapper memory exhaustion

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `src/crypto/internal/fips140test/acvp_test.go:364`
- Patched at `src/crypto/internal/fips140test/acvp_test.go:386`

## Summary
`readRequest` accepted an unbounded little-endian `numArgs` from stdin and passed it to `readArgs`, which immediately allocated `make([]uint32, requiredArgs)` and `make([][]byte, requiredArgs)` with attacker-controlled size. This occurs before command lookup, unknown-command rejection, or per-command `requiredArgs` checks, so a crafted ACVP wrapper request can force large heap growth or process termination.

## Provenance
- Verified finding reproduced from the supplied code and reproducer summary
- Scanner source: [Swival Security Scanner](https://swival.dev)

## Preconditions
- Attacker can send ACVP wrapper stdin requests
- The binary is running with `ACVP_WRAPPER=1`, which enters `processingLoop` on stdin

## Proof
- In `readRequest`, `numArgs` is read directly from stdin via `binary.Read(reader, binary.LittleEndian, &numArgs)`.
- Before the patch, the only validation was `numArgs == 0`; any larger value was accepted.
- `readArgs(reader, numArgs)` then allocated:
  - `make([]uint32, requiredArgs)`
  - `make([][]byte, requiredArgs)`
- The reproducer set `numArgs = 10_000_000` and supplied zero-valued length words, producing `args 10000000` and about `320061120` bytes of heap growth, consistent with the two slice allocations alone.
- This allocation path is reached before `req.name` is checked in `processingLoop`, so even invalid or unknown commands trigger the memory pressure.

## Why This Is A Real Bug
The bug is directly reachable from untrusted stdin in wrapper mode and causes linear attacker-controlled memory allocation before any semantic validation. The reproduced heap growth confirms practical exploitability. At sufficiently large values, the wrapper can be killed by OOM or allocation failure, making this a real denial-of-service condition within the ACVP wrapper threat model.

## Fix Requirement
Reject excessive `numArgs` before calling `readArgs`, using a strict protocol maximum derived from the wrapper’s supported command surface.

## Patch Rationale
The patch introduces `const maxRequestArgs uint32 = 9` and enforces `if numArgs > maxRequestArgs { return nil, fmt.Errorf("invalid request: too many args: %d", numArgs) }` in `readRequest`. This blocks oversized requests before any attacker-sized slice allocation. The chosen bound is protocol-appropriate because it covers the command name plus the maximum supported argument count in the registered commands.

## Residual Risk
None

## Patch
```diff
diff --git a/src/crypto/internal/fips140test/acvp_test.go b/src/crypto/internal/fips140test/acvp_test.go
index 6a0b46af2b..38be9034bb 100644
--- a/src/crypto/internal/fips140test/acvp_test.go
+++ b/src/crypto/internal/fips140test/acvp_test.go
@@ -119,6 +119,8 @@ const (
 	aesDecrypt
 )
 
+const maxRequestArgs uint32 = 9 // Command name plus the maximum supported argument count.
+
 var (
 
 	// Separate capabilities specific to testing the entropy source's SHA2-384 implementation.
@@ -384,6 +386,9 @@ func readRequest(reader io.Reader) (*request, error) {
 	if numArgs == 0 {
 		return nil, errors.New("invalid request: zero args")
 	}
+	if numArgs > maxRequestArgs {
+		return nil, fmt.Errorf("invalid request: too many args: %d", numArgs)
+	}
 
 	args, err := readArgs(reader, numArgs)
 	if err != nil {
```