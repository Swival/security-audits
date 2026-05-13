# GitHub Actions Command Injection Via Timeout Test Name

## Classification

Injection, medium severity. Confidence: certain.

## Affected Locations

`src/runtime/cli/test_command.rs:779`

## Summary

`CommandLineReporter::print_test_line` emitted GitHub Actions `::error` annotations for timed-out tests using the raw test name. An attacker-controlled test name containing newlines and workflow-command syntax could break out of the annotation line and forge additional GitHub Actions commands in CI logs.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Tests run in GitHub Actions.
- An attacker can contribute or influence a test name.
- The attacker can make that test time out.

## Proof

A malicious pull request can define:

```js
test("owned\n::warning title=pwned::forged\n", () => new Promise(() => {}), {
  timeout: 1,
});
```

The test runner accepts string descriptions, stores them unchanged, and applies caller-provided timeout options. On timeout, the GitHub Actions path emitted a line equivalent to:

```text
::error title=error: Test "owned
::warning title=pwned::forged
" timed out after 1ms::
```

The injected second line is a valid GitHub Actions workflow command, allowing forged annotations or other supported workflow-command effects in CI logs.

## Why This Is A Real Bug

The vulnerable sink only runs when `Output::is_github_action()` is true, exactly when GitHub parses workflow commands from log output. The attacker-controlled `display_label` came from `test_entry.base.name` and was interpolated directly into the annotation property without escaping `%`, carriage returns, line feeds, colons, or commas. Newline injection therefore creates a separate workflow-command line.

## Fix Requirement

Escape attacker-controlled data before embedding it in GitHub Actions workflow-command annotation properties.

## Patch Rationale

The patch adds a `GithubActionProperty` formatter and `github_action_property()` helper that percent-encodes GitHub Actions property metacharacters:

- `%` as `%25`
- `\r` as `%0D`
- `\n` as `%0A`
- `:` as `%3A`
- `,` as `%2C`

`CommandLineReporter::print_test_line` now formats the timeout annotation title with `github_action_property(display_label)` instead of raw `bstr::BStr::new(display_label)`, preventing line breaks or command delimiters from being interpreted as workflow syntax.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/cli/test_command.rs b/src/runtime/cli/test_command.rs
index 70691b02a4..1c3f895c30 100644
--- a/src/runtime/cli/test_command.rs
+++ b/src/runtime/cli/test_command.rs
@@ -199,7 +199,38 @@ pub fn escape_xml(str_: &[u8], writer: &mut impl bun_io::Write) -> Result<(), bu
     Ok(())
 }
 
-fn fmt_status_text_line(
+struct GithubActionProperty<'a>(&'a [u8]);
+
+impl core::fmt::Display for GithubActionProperty<'_> {
+    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
+        let mut last: usize = 0;
+        for (i, byte) in self.0.iter().copied().enumerate() {
+            let escaped = match byte {
+                b'%' => "%25",
+                b'\r' => "%0D",
+                b'\n' => "%0A",
+                b':' => "%3A",
+                b',' => "%2C",
+                _ => continue,
+            };
+            if i > last {
+                write!(f, "{}", bstr::BStr::new(&self.0[last..i]))?;
+            }
+            f.write_str(escaped)?;
+            last = i + 1;
+        }
+        if last < self.0.len() {
+            write!(f, "{}", bstr::BStr::new(&self.0[last..]))?;
+        }
+        Ok(())
+    }
+}
+
+fn github_action_property(value: &[u8]) -> GithubActionProperty<'_> {
+    GithubActionProperty(value)
+}
+
+fn fmt_status_text_line(
     status: bun_test::Execution::Result,
     emoji_or_color: bool,
 ) -> Output::PrettyBuf {
@@ -951,7 +982,7 @@ impl CommandLineReporter {
                     if Output::is_github_action() {
                         Output::print_error(format_args!(
                             "::error title=error: Test \"{}\" timed out after {}ms::\n",
-                            bstr::BStr::new(display_label),
+                            github_action_property(display_label),
                             test_entry.timeout
                         ));
                         Output::flush();
```