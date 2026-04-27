# Unescaped JUnit XML Attribute Values

## Classification

Validation gap, medium severity.

## Affected Locations

`library/test/src/formatters/junit.rs:106`

## Summary

The JUnit formatter writes test descriptor-derived strings directly into XML attributes without escaping. Test names or paths containing XML metacharacters such as `&`, `<`, `>`, or `"` can produce malformed JUnit XML or inject additional attributes into `<testcase>` elements.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Test descriptors can contain XML metacharacters in names or paths.

## Proof

`write_result` stores `desc.clone()` in `self.results` without validating or normalizing descriptor names.

During `write_run_finish`, each descriptor is passed to `parse_class_name(&desc)`, which derives `class_name` and `test_name` from `desc.name`. Those values are then interpolated directly into XML attributes such as:

```rust
<testcase classname="{}" name="{}" time="{}">
```

This occurs across the JUnit formatter’s result branches, including failed, failed-with-message, timed-fail, benchmark, and successful test cases.

A descriptor name such as:

```text
suite::bad" injected="x & <
```

can produce a testcase fragment equivalent to:

```xml
<testcase classname="suite" name="bad" injected="x & <" time="0"/>
```

That output is malformed XML and can alter the attribute structure before XML parsing fails or parser behavior diverges.

The surrounding code already treats stdout as XML-sensitive by wrapping it in escaped CDATA, confirming that generated JUnit output is expected to be well-formed XML.

## Why This Is A Real Bug

JUnit output is consumed by XML parsers in CI systems, test report aggregators, IDEs, and build tooling. Unescaped descriptor-derived attribute values make the emitted report invalid for legitimate test names containing XML metacharacters and allow attribute injection in generated XML.

The issue is reachable for every non-ignored result emitted by the JUnit formatter because all such results pass through `write_run_finish` and write `class_name` and `test_name` into attributes.

## Fix Requirement

All XML attribute values derived from test descriptors or failure messages must be XML-escaped before being formatted into JUnit elements.

At minimum, attribute escaping must cover:

```text
&  -> &amp;
<  -> &lt;
>  -> &gt;
"  -> &quot;
```

## Patch Rationale

The patch adds `str_to_xml_attr`, which escapes XML metacharacters that are unsafe in double-quoted attribute values.

It then applies this escaping once per testcase after `parse_class_name(&desc)` returns:

```rust
let class_name = str_to_xml_attr(&class_name);
let test_name = str_to_xml_attr(&test_name);
```

Because all testcase branches reuse those local variables, the fix covers failed, timed-out, benchmark, and successful test output paths.

The patch also escapes `TrFailedMsg` failure messages before placing them in the `<failure message="...">` attribute, addressing the same attribute-context bug for assertion messages.

## Residual Risk

None

## Patch

```diff
diff --git a/library/test/src/formatters/junit.rs b/library/test/src/formatters/junit.rs
index 2772222a05c..66575df9a23 100644
--- a/library/test/src/formatters/junit.rs
+++ b/library/test/src/formatters/junit.rs
@@ -37,6 +37,10 @@ fn str_to_cdata(s: &str) -> String {
     format!("<![CDATA[{}]]>", escaped_output)
 }
 
+fn str_to_xml_attr(s: &str) -> String {
+    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
+}
+
 impl<T: Write> OutputFormatter for JunitFormatter<T> {
     fn write_discovery_start(&mut self) -> io::Result<()> {
         Err(io::const_error!(io::ErrorKind::NotFound, "not yet implemented!"))
@@ -98,6 +102,8 @@ fn write_run_finish(&mut self, state: &ConsoleTestState) -> io::Result<bool> {
         ))?;
         for (desc, result, duration, stdout) in std::mem::take(&mut self.results) {
             let (class_name, test_name) = parse_class_name(&desc);
+            let class_name = str_to_xml_attr(&class_name);
+            let test_name = str_to_xml_attr(&test_name);
             match result {
                 TestResult::TrIgnored => { /* no-op */ }
                 TestResult::TrFailed => {
@@ -125,7 +131,10 @@ fn write_run_finish(&mut self, state: &ConsoleTestState) -> io::Result<bool> {
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