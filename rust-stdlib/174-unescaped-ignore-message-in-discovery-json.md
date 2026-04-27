# Unescaped Ignore Message In Discovery JSON

## Classification

- Finding type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations

- `library/test/src/formatters/json.rs:72`

## Summary

`JsonFormatter::write_test_discovered` writes `TestDesc::ignore_message` directly into a JSON string field. Unlike nearby `name` and `source_path` fields, the value is not passed through `EscapedString`, so quotes, backslashes, and control characters can corrupt the discovery JSON or inject additional JSON fields for downstream consumers.

## Provenance

- Source: Swival Security Scanner
- URL: https://swival.dev
- Status: reproduced and patched

## Preconditions

- Test discovery is run with JSON output.
- A discovered ignored test has an `ignore_message` containing JSON metacharacters such as `"`, `\`, or newline.

## Proof

The vulnerable code unwraps the optional ignore message and formats it directly inside a JSON string:

```rust
let ignore_message = ignore_message.unwrap_or("");

r#"... "ignore_message": "{ignore_message}", ..."#
```

A reproducer using an ignored test with metacharacters confirms malformed JSON output:

```rust
#[test]
#[ignore = "bad \" quote \\ slash\nand newline"]
fn ignored_with_json_metachars() {}
```

Run with JSON discovery output:

```sh
rustc --test ignore_json.rs -o ignore_json_test
RUSTC_BOOTSTRAP=1 ./ignore_json_test --list --format json -Z unstable-options
```

The discovery event emits raw JSON metacharacters inside the string:

```text
{ "type": "test", "event": "discovered", "name": "ignored_with_json_metachars", "ignore": true, "ignore_message": "bad " quote \ slash
and newline", "source_path": "...", "start_line": 3, ... }
```

A line-oriented JSON parser fails with `JSONDecodeError` because the event is split and corrupted.

A second proof of concept using:

```rust
#[ignore = "\", \"injected\": true, \"ignore_message\": \""]
```

produces syntactically valid JSON containing an injected `"injected": true` field.

## Why This Is A Real Bug

The formatter advertises JSON output, but an attacker-controlled or project-controlled ignore message can make the emitted discovery event invalid JSON or alter the object shape consumed by automation. This affects downstream tools that parse `--list --format json -Z unstable-options` output for test inventory, policy enforcement, or CI reporting.

The same formatter already escapes other string fields in this function, including `name` and `source_path`, and escapes ignored-test result messages elsewhere. The inconsistent treatment of `ignore_message` is therefore a concrete escaping omission, not an expected limitation.

## Fix Requirement

`ignore_message` must be JSON-escaped before being interpolated into the discovery event string.

## Patch Rationale

Wrapping the unwrapped ignore message with `EscapedString` applies the formatter’s existing JSON string escaping logic to the discovery `ignore_message` field. This preserves current output for safe strings while correctly escaping quotes, backslashes, newlines, and control characters.

## Residual Risk

None

## Patch

```diff
diff --git a/library/test/src/formatters/json.rs b/library/test/src/formatters/json.rs
index 4a101f00d74..12ad3bb160b 100644
--- a/library/test/src/formatters/json.rs
+++ b/library/test/src/formatters/json.rs
@@ -75,7 +75,7 @@ fn write_test_discovered(&mut self, desc: &TestDesc, test_type: &str) -> io::Res
         } = desc;
 
         let name = EscapedString(name.as_slice());
-        let ignore_message = ignore_message.unwrap_or("");
+        let ignore_message = EscapedString(ignore_message.unwrap_or(""));
         let source_path = EscapedString(source_file);
         let newline = "\n";
```