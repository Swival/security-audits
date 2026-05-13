# Newline in Source Path Injects LCOV Records

## Classification

Injection, low severity.

## Affected Locations

`src/sourcemap_jsc/CodeCoverage.rs:251`

`src/sourcemap_jsc/CodeCoverage.rs:304`

`src/sourcemap_jsc/CodeCoverage.rs:311`

`src/runtime/cli/test/parallel/aggregate.rs:174`

## Summary

LCOV generation wrote `Report.source_url` into the `SF:` field without escaping embedded carriage-return or line-feed bytes. If an attacker controlled a project filename containing `\n` or `\r`, the generated LCOV stream could include forged records such as `DA:` or `end_of_record`, altering downstream coverage interpretation.

## Provenance

Verified and reproduced from Swival.dev Security Scanner findings: https://swival.dev

Confidence: certain.

## Preconditions

LCOV generation must run on project paths controlled by an attacker, such as a lower-privileged local user able to create project filenames.

## Proof

`ByteRangeMapping__generate` stores the source path string as `source_url`.

`Report` generation carries that value into `Report.source_url` in `src/sourcemap_jsc/CodeCoverage.rs:407`.

LCOV output derives `filename` directly from `report.source_url.slice()` in `src/sourcemap_jsc/CodeCoverage.rs:304`.

The vulnerable writer emitted the path directly:

```rust
write!(writer, "SF:{}\n", bstr::BStr::new(filename))?;
```

`bstr::BStr` display does not escape embedded LF bytes. A filename containing LCOV syntax therefore becomes structural LCOV output.

Example resulting fragment shape:

```lcov
TN:
SF:evil
end_of_record
TN:
SF:forged.ts
DA:1,1
LF:1
LH:1
end_of_record
TN:
SF:evil
FNF:...
```

Downstream parsers, including Bun’s parallel coverage merger that splits records on `\n` and treats `SF:`, `DA:`, and `end_of_record` structurally, can consume the injected records.

## Why This Is A Real Bug

LCOV is a line-oriented format. The `SF:` value is data, but unescaped CR/LF bytes terminate the field and start new records. Because the path comes from project filenames and is written verbatim into LCOV output, attacker-controlled filenames can modify report structure and coverage results.

## Fix Requirement

Reject or escape CR/LF bytes in LCOV path fields before writing them to the output stream.

## Patch Rationale

The patch replaces the single formatted write with explicit field emission. It writes `SF:`, iterates over each byte of `filename`, replaces `\n` and `\r` with `?`, writes all other bytes unchanged, then writes the terminating newline.

This preserves normal path output while ensuring attacker-controlled path bytes cannot create additional LCOV lines or records.

## Residual Risk

None

## Patch

```diff
diff --git a/src/sourcemap_jsc/CodeCoverage.rs b/src/sourcemap_jsc/CodeCoverage.rs
index e0895e7d47..942048188b 100644
--- a/src/sourcemap_jsc/CodeCoverage.rs
+++ b/src/sourcemap_jsc/CodeCoverage.rs
@@ -312,7 +312,14 @@ pub mod lcov {
 
         // SF: Source File path
         // For example, `SF:path/to/source.ts`
-        write!(writer, "SF:{}\n", bstr::BStr::new(filename))?;
+        writer.write_all(b"SF:")?;
+        for &byte in filename {
+            match byte {
+                b'\n' | b'\r' => writer.write_all(b"?")?,
+                byte => writer.write_all(&[byte])?,
+            }
+        }
+        writer.write_all(b"\n")?;
 
         // ** Per-function coverage not supported yet, since JSC does not support function names yet. **
         // FN: line number,function name
```