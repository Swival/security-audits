# Bidi Controls Spoof Approval Prompt Paths

## Classification

Policy bypass, medium severity.

## Affected Locations

`crates/nono-cli/src/terminal_approval.rs:115`

## Summary

`TerminalApproval` displayed attacker-controlled `request.path` and `request.reason` after sanitization, but the sanitizer only removed ANSI escape sequences and Rust `is_control()` characters. Unicode bidirectional formatting characters such as U+202E are not Rust control characters, so they survived sanitization and could visually reorder text in terminals that render bidi controls.

A sandboxed child process could request access to one filesystem path while presenting a visually disguised path in the approval prompt. If the operator approved, the original unmodified path remained the granted capability target.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A sandboxed child process can trigger a filesystem capability request.
- The request path or reason can include Unicode bidirectional formatting characters.
- The operator terminal renders Unicode bidi controls in the approval prompt.
- The operator relies on the displayed prompt text when granting access.

## Proof

`request_capability` prints untrusted fields:

- `request.path.display().to_string()` is passed to `sanitize_for_terminal`.
- `request.reason` is passed to `sanitize_for_terminal`.
- The sanitized strings are printed in the terminal approval prompt.

The sanitizer removed ANSI escape sequences and replaced `c.is_control()` characters with spaces. Unicode bidi controls such as U+202E are format characters, not Rust control characters, so they reached `result.push(c)` unchanged.

The reproduced check confirmed:

```rust
'\u{202E}'.is_control() == false
```

The sanitizer output still contained U+202E.

If the operator answers `y`, `TerminalApproval` returns `ApprovalDecision::Granted`. The supervisor then opens or sends the original `request.path` after approval, so the granted capability still targets the original path rather than the visually rendered prompt text.

## Why This Is A Real Bug

The approval prompt is a security boundary: it asks a human operator to authorize additional filesystem access for an untrusted sandboxed process.

Because bidi controls can alter visual ordering without changing the underlying string, the operator can be shown a misleading path while the program grants access to the attacker-selected original path. This creates a practical approval-policy bypass under the stated terminal-rendering precondition.

## Fix Requirement

Strip or visibly escape Unicode bidirectional formatting characters before printing attacker-controlled approval prompt fields.

The protection must apply to both:

- Requested path display text.
- Request reason display text.

## Patch Rationale

The patch extends `sanitize_for_terminal` so it treats Unicode bidi controls like other unsafe terminal-control content. Instead of allowing them through to `result.push(c)`, the sanitizer replaces them with spaces.

The added denylist covers common bidi formatting controls:

- U+061C Arabic Letter Mark.
- U+200E Left-To-Right Mark.
- U+200F Right-To-Left Mark.
- U+202A through U+202E embedding and override controls.
- U+2066 through U+2069 isolate controls.

This preserves readable surrounding text while preventing invisible formatting controls from changing how the approval prompt is rendered.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono-cli/src/terminal_approval.rs b/crates/nono-cli/src/terminal_approval.rs
index a0d9bc8..2e065a1 100644
--- a/crates/nono-cli/src/terminal_approval.rs
+++ b/crates/nono-cli/src/terminal_approval.rs
@@ -66,8 +66,8 @@ impl ApprovalBackend for TerminalApproval {
     }
 }
 
-/// Strip control characters and ANSI escape sequences from untrusted input
-/// before displaying on the terminal.
+/// Strip control characters, Unicode bidi controls, and ANSI escape sequences
+/// from untrusted input before displaying on the terminal.
 ///
 /// Handles all standard escape sequence types:
 /// - CSI (ESC [): cursor movement, SGR colors, erase commands
@@ -107,7 +107,12 @@ fn sanitize_for_terminal(input: &str) -> String {
             continue;
         }
 
-        if c.is_control() {
+        if c.is_control()
+            || matches!(
+                c,
+                '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
+            )
+        {
             result.push(' ');
         } else {
             result.push(c);
```