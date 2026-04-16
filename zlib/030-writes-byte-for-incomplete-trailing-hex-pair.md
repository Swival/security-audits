# Writes byte for incomplete trailing hex pair

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `contrib/puff/bin-writer.c:15`

## Summary
- `bin-writer` reads hex input from `stdin` two characters at a time and writes the decoded byte.
- When input ends after a single trailing hex nibble, the first `getchar()` succeeds but the second returns `EOF`.
- The original code still passed that incomplete pair to `strtol()` and then `fwrite()`, causing one byte to be emitted from malformed input.
- This appends corrupted output for odd-length hex streams instead of rejecting or stopping before the partial byte.

## Provenance
- Verified from the supplied reproducer and patch target in `contrib/puff/bin-writer.c`
- Reproduced locally from the described control flow and runtime behavior
- Scanner reference: https://swival.dev

## Preconditions
- `stdin` ends after a single trailing hex nibble

## Proof
- In `contrib/puff/bin-writer.c:15`, the loop reads the first hex digit into `hexStr[0]`.
- The next read at `contrib/puff/bin-writer.c:16` can return `EOF` when input has an odd number of hex digits.
- The original implementation still null-terminated `hexStr`, called `strtol(hexStr, &endptr, 16)`, and wrote the resulting byte with `fwrite`.
- Runtime reproducer: `printf 'A' | bin-writer | od -An -tx1` outputs `0a`, proving that a lone trailing nibble still becomes a byte.

## Why This Is A Real Bug
- The program claims to decode hex pairs into bytes, so emitting a byte for only one nibble violates its input contract.
- `strtol()` accepting the first nibble does not make the input complete; it only masks the malformed trailing pair.
- The resulting output is observably wrong and deterministic, so this is a concrete integrity failure rather than a theoretical parser concern.

## Fix Requirement
- Check the second `getchar()` result for `EOF` before calling `strtol()` or `fwrite()`.
- If the pair is incomplete, abort processing or return an error without emitting a byte.

## Patch Rationale
- The patch in `030-writes-byte-for-incomplete-trailing-hex-pair.patch` adds an explicit `EOF` check on the second nibble read.
- This preserves existing behavior for valid even-length input while preventing partial trailing pairs from reaching conversion and write paths.
- The fix is minimal and directly closes the demonstrated corruption path.

## Residual Risk
- None

## Patch
```diff
diff --git a/contrib/puff/bin-writer.c b/contrib/puff/bin-writer.c
--- a/contrib/puff/bin-writer.c
+++ b/contrib/puff/bin-writer.c
@@ -13,8 +13,14 @@ int main()
     while ((nextChar = getchar()) != EOF)
     {
         hexStr[0] = nextChar;
-        hexStr[1] = (char)getchar();
+        nextChar = getchar();
+        if (nextChar == EOF)
+        {
+            fprintf(stderr, "error: incomplete trailing hex pair\n");
+            return 1;
+        }
+
+        hexStr[1] = (char)nextChar;
         hexStr[2] = '\0';
         val = strtol(hexStr, &endptr, 16);
         fwrite(&val, 1, 1, stdout);
```