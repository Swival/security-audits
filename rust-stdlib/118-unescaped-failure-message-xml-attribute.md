# Unescaped Failure Message XML Attribute

## Classification

Data integrity bug, medium severity, confirmed.

## Affected Locations

`library/test/src/formatters/junit.rs:135`

## Summary

`JunitFormatter` emitted `TestResult::TrFailedMsg` directly into the JUnit `<failure message="...">` XML attribute without escaping XML metacharacters. Failure messages containing `&`, `"`, `'`, `<`, or `>` could produce malformed XML or alter the structure of the generated JUnit report.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A failing test returns `TestResult::TrFailedMsg` containing XML metacharacters.

## Proof

`write_result` stores `TestResult` values unchanged in `self.results`.

During `write_run_finish`, the formatter matches `TestResult::TrFailedMsg(ref m)` and writes:

```rust
self.write_message(&format!("<failure message=\"{m}\" type=\"assert\"/>"))?;
```

No XML attribute escaping is applied to `m`.

A practical trigger exists for `#[should_panic]` tests that do not panic. The failure message is constructed from source location data, so a source path containing XML metacharacters can reach the JUnit attribute.

Confirmed runtime output from a test file under a directory named `a&b`:

```xml
<failure message="test did not panic as expected at .../a&b/f.rs:3:4" type="assert"/>
```

Parsing that output with Python's XML parser fails with:

```text
ParseError: not well-formed (invalid token)
```

The unescaped ampersand makes the generated JUnit XML invalid. Embedded quote characters would also permit attribute injection.

## Why This Is A Real Bug

JUnit XML is consumed by CI systems, test report parsers, and automation tooling. Emitting unescaped user- or environment-influenced text into an XML attribute violates XML encoding rules and can break downstream consumers.

The existing `str_to_cdata` helper only protects stdout content inside CDATA. It is not used for the `failure` message attribute and does not address attribute-context escaping.

## Fix Requirement

Escape XML attribute metacharacters before inserting failure messages into the `message` attribute.

Required replacements:

```text
&  -> &amp;
"  -> &quot;
'  -> &apos;
<  -> &lt;
>  -> &gt;
```

## Patch Rationale

The patch adds a dedicated `str_to_xml_attr` helper for XML attribute escaping:

```rust
fn str_to_xml_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
```

It then applies that helper when writing `TrFailedMsg`:

```rust
self.write_message(&format!(
    "<failure message=\"{}\" type=\"assert\"/>",
    str_to_xml_attr(m)
))?;
```

Escaping `&` first prevents double-interpreting ampersands introduced by later entity replacements. The change is narrowly scoped to the vulnerable XML attribute sink.

## Residual Risk

None

## Patch

```diff
diff --git a/library/test/src/formatters/junit.rs b/library/test/src/formatters/junit.rs
index 2772222a05c..9eb0a3b54db 100644
--- a/library/test/src/formatters/junit.rs
+++ b/library/test/src/formatters/junit.rs
@@ -37,6 +37,14 @@ fn str_to_cdata(s: &str) -> String {
     format!("<![CDATA[{}]]>", escaped_output)
 }
 
+fn str_to_xml_attr(s: &str) -> String {
+    s.replace('&', "&amp;")
+        .replace('"', "&quot;")
+        .replace('\'', "&apos;")
+        .replace('<', "&lt;")
+        .replace('>', "&gt;")
+}
+
 impl<T: Write> OutputFormatter for JunitFormatter<T> {
     fn write_discovery_start(&mut self) -> io::Result<()> {
         Err(io::const_error!(io::ErrorKind::NotFound, "not yet implemented!"))
@@ -125,7 +133,10 @@ fn write_run_finish(&mut self, state: &ConsoleTestState) -> io::Result<bool> {
                         test_name,
                         duration.as_secs_f64()
                     ))?;
-                    self.write_message(&format!("<failure message=\"{m}\" type=\"assert\"/>"))?;
+                    self.write_message(&format!(
+                        "<failure message=\"{}\" type=\"assert\"/>",
+                        str_to_xml_attr(m)
+                    ))?;
                     if !stdout.is_empty() {
                         self.write_message("<system-out>")?;
                         self.write_message(&str_to_cdata(&String::from_utf8_lossy(&stdout)))?;
```