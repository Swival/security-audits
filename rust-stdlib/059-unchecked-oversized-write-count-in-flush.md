# Unchecked Oversized Write Count In BufWriter Flush

## Classification

- Type: invariant violation
- Severity: low
- Confidence: certain

## Affected Locations

- `library/std/src/io/buffered/bufwriter.rs:238`
- `library/std/src/io/buffered/bufwriter.rs:246`
- `library/std/src/io/buffered/bufwriter.rs:228`

## Summary

`BufWriter::flush_buf` trusts the byte count returned by the wrapped `Write::write` implementation. If the inner writer returns `Ok(n)` where `n` is greater than the length of the slice it was given, `flush_buf` records too many bytes as consumed. That breaks the internal `BufGuard` invariant and can cause `Vec::drain(..written)` to panic when the guard is dropped.

The patch rejects oversized successful write counts before consuming them.

## Provenance

- Source: Swival Security Scanner
- Scanner URL: https://swival.dev
- Finding: unchecked oversized write count in flush

## Preconditions

- A `BufWriter<W>` contains buffered bytes.
- The wrapped `W: Write` implementation returns `Ok(n)` from `write`.
- `n` is greater than the length of the input slice passed to `write`.

## Proof

Buffered data reaches `flush_buf` through `BufWriter::write`, `write_all`, or related buffering paths.

Inside `flush_buf`, the current unwritten buffer is passed to the inner writer:

```rust
let r = self.inner.write(guard.remaining());
```

Before the patch, any nonzero `Ok(n)` was accepted:

```rust
Ok(n) => guard.consume(n),
```

`BufGuard::consume` only increments `written`:

```rust
fn consume(&mut self, amt: usize) {
    self.written += amt;
}
```

If `n > guard.remaining().len()`, then `written` can exceed `buffer.len()`. When `BufGuard` is dropped, it drains the consumed prefix:

```rust
self.buffer.drain(..self.written);
```

With `written > buffer.len()`, this becomes an out-of-range drain and panics.

A safe proof-of-concept writer returning `Ok(buf.len() + 1)` reproduces the issue: buffering `b"abc"` in `BufWriter` and calling `flush` panics with `range end index 4 out of range for slice of length 3`.

## Why This Is A Real Bug

The `Write` trait contract requires implementations not to report more bytes written than were provided, but `BufWriter` is a safe abstraction over arbitrary safe `Write` implementations. A buggy or malicious safe `Write` can violate that contract without unsafe code.

Before the patch, that contract violation was converted into an internal `BufWriter` invariant violation. The result was an unexpected panic in `flush`, `into_inner`, `seek`, or `drop`. In `drop`, a panic during unwinding can abort the process.

## Fix Requirement

`flush_buf` must validate successful write counts before updating `BufGuard::written`.

If `write` returns `Ok(n)` where `n > guard.remaining().len()`, `flush_buf` must not call `guard.consume(n)`. It should instead return an explicit error, such as `ErrorKind::InvalidData`.

## Patch Rationale

The patch adds a guard before the existing `Ok(n) => guard.consume(n)` arm:

```rust
Ok(n) if n > guard.remaining().len() => {
    return Err(io::const_error!(
        ErrorKind::InvalidData,
        "write returned more bytes than provided",
    ));
}
```

This preserves the existing handling for:

- `Ok(0)`: returns `WriteZero`
- valid `Ok(n)`: consumes exactly the reported bytes
- interrupted errors: retries
- other errors: propagates the error

The new check prevents `written` from exceeding the actual buffer length and therefore prevents `BufGuard::drop` from calling `Vec::drain` with an invalid range.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/io/buffered/bufwriter.rs b/library/std/src/io/buffered/bufwriter.rs
index 1b34724e6cc..5166fc77904 100644
--- a/library/std/src/io/buffered/bufwriter.rs
+++ b/library/std/src/io/buffered/bufwriter.rs
@@ -243,6 +243,12 @@ fn drop(&mut self) {
                         "failed to write the buffered data",
                     ));
                 }
+                Ok(n) if n > guard.remaining().len() => {
+                    return Err(io::const_error!(
+                        ErrorKind::InvalidData,
+                        "write returned more bytes than provided",
+                    ));
+                }
                 Ok(n) => guard.consume(n),
                 Err(ref e) if e.is_interrupted() => {}
                 Err(e) => return Err(e),
```