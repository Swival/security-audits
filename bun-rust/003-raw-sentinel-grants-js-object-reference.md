# Raw Sentinel Grants JS Object Reference

## Classification

High severity authorization bypass.

Confidence: certain.

## Affected Locations

- `src/shell_parser/parse.rs:1641`
- `src/shell_parser/parse.rs:1644`
- `src/shell_parser/parse.rs:2411`
- `src/shell_parser/parse.rs:2412`
- `src/shell_parser/parse.rs:2413`
- `src/shell_parser/parse.rs:2654`
- `src/shell_parser/parse.rs:3794`

## Summary

Raw attacker-controlled shell bytes could encode Bun's internal JS object substitution sentinel, causing the lexer to emit `Token::JSObjRef`. The parser accepted that token as a redirect target and emitted `Redirect::JsBuf(idx)`, allowing an attacker to redirect command output into an existing caller-provided JS object by index.

## Provenance

Reported and reproduced from Swival.dev Security Scanner findings.

Scanner URL: https://swival.dev

## Preconditions

- Caller provides at least one JS object substitution to the shell parser.
- Caller parses attacker-controlled shell bytes in the same shell script.
- Attacker can include raw sentinel bytes in the shell source.

## Proof

A raw shell fragment containing the legacy sentinel can select object index `0`:

```text
echo pwned > \x08__bun_0
```

Lexer behavior:

- `Lexer::lex` treats `SPECIAL_JS_CHAR` in source as the start of an internal substitution marker.
- `looks_like_js_obj_ref` and `eat_js_obj_ref` parse `\x08__bun_<digits>`.
- Validation only checks `idx < jsobjs_len`.
- A valid marker emits `Token::JSObjRef(idx)`.

Parser behavior:

- `Parser::parse_redirect` accepts `Token::JSObjRef` immediately after `Token::Redirect`.
- It emits `Redirect::JsBuf(ast::JSBuf::new(obj_ref))`.

Runtime behavior:

- Runtime redirection resolves `interp.jsobjs[idx]`.
- The selected object is wired as an ArrayBuffer, Blob, stdin, stdout, or stderr target.

Impact:

- The attacker does not receive the JS object capability directly.
- The attacker can nevertheless select an existing caller-provided JS object by index.
- For an ArrayBuffer target, command output is written into that object, giving unintended integrity over caller-owned data.

## Why This Is A Real Bug

The sentinel was meant to represent trusted substitutions inserted by Bun internals, not bytes supplied by shell source. Because the previous sentinel byte was `\x08`, raw source could contain it and be interpreted as a trusted substitution. The only authorization check was an in-bounds index check, which verifies memory safety but not capability ownership.

This crosses a trust boundary: attacker-controlled source can manufacture a parser token that should only be produced by trusted substitution plumbing.

## Fix Requirement

Raw shell source must not be able to smuggle internal substitution sentinels. Trusted substitutions must be distinguishable from attacker-controlled bytes, or raw sentinels must be rejected or escaped before lexing.

## Patch Rationale

The patch changes the internal sentinel from backspace byte `\x08` to NUL byte `\0`:

```diff
-const SPECIAL_JS_CHAR: u8 = 8;
-pub const LEX_JS_OBJREF_PREFIX: &[u8] = b"\x08__bun_";
-pub const LEX_JS_STRING_PREFIX: &[u8] = b"\x08__bunstr_";
+const SPECIAL_JS_CHAR: u8 = 0;
+pub const LEX_JS_OBJREF_PREFIX: &[u8] = b"\0__bun_";
+pub const LEX_JS_STRING_PREFIX: &[u8] = b"\0__bunstr_";
```

The source comment documents the security invariant: NUL is rejected from user-provided shell strings before lexing, so raw source bytes cannot encode the internal sentinel.

This preserves trusted substitution parsing while removing the ability for attacker-controlled shell text to synthesize `Token::JSObjRef`.

## Residual Risk

None

## Patch

Applied in `003-raw-sentinel-grants-js-object-reference.patch`:

- `src/shell_parser/parse.rs:2406` changes the internal substitution sentinel from `\x08` to `\0`.
- `src/shell_parser/parse.rs:2409` updates `LEX_JS_OBJREF_PREFIX` to `b"\0__bun_"`.
- `src/shell_parser/parse.rs:2410` updates `LEX_JS_STRING_PREFIX` to `b"\0__bunstr_"`.
- `src/shell_parser/parse.rs:2649` updates the lexer comment to reflect internal substitution handling.