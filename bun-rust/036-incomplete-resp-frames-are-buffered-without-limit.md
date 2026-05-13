# Incomplete RESP Frames Buffered Without Limit

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`src/runtime/valkey_jsc/valkey.rs:764`

## Summary

`ValkeyClient::on_data` buffered partial RESP frames in `self.read_buffer` without any maximum size. An attacker-controlled Valkey endpoint could continuously send incomplete RESP data, causing unbounded heap growth in the client process until memory exhaustion.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- A client connects to an attacker-controlled Valkey endpoint.
- The endpoint can send RESP data that remains syntactically incomplete.

## Proof

`on_data` has two relevant paths:

- Empty-buffer path: when parsing `current_data_slice` fails with `RedisError::InvalidResponse`, the code treats it as a partial RESP value and writes `current_data_slice[before_read_pos..]` into `self.read_buffer`.
- Nonempty-buffer path: every later call appends all new peer-controlled bytes to `self.read_buffer` before parsing.
- If parsing still returns `RedisError::InvalidResponse`, `on_data` returns `Ok(())` without consuming or bounding the buffer.
- The backing `OffsetByteList::write` ultimately extends a `Vec` and imposes no maximum.

A malicious server can keep the RESP frame incomplete indefinitely, making `read_buffer` grow until allocation failure or process termination.

## Why This Is A Real Bug

This is peer-triggered and does not require authentication bypass or malformed local state. The Valkey server is a network peer, and the client explicitly accepts partial RESP values as needing more data. Because the accumulated bytes are never capped, attacker-controlled input directly drives unbounded heap allocation.

## Fix Requirement

Enforce a maximum `read_buffer` size and fail or close the connection when incoming partial data would exceed that limit.

## Patch Rationale

The patch adds `MAX_READ_BUFFER_SIZE` set to `16 * 1024 * 1024` bytes and checks both accumulation points:

- Before appending new socket data to an existing `read_buffer`.
- Before copying remaining stack data into an empty `read_buffer` after an incomplete parse.

When the limit would be exceeded, the client:

- Marks the connection as manually closed.
- Clears and frees `read_buffer`.
- Fails pending work with `RedisError::InvalidResponse`.
- Closes the socket.

This bounds memory growth while preserving normal handling for partial RESP frames under the limit.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/valkey_jsc/valkey.rs b/src/runtime/valkey_jsc/valkey.rs
index 9481fa7fdb..090d541f34 100644
--- a/src/runtime/valkey_jsc/valkey.rs
+++ b/src/runtime/valkey_jsc/valkey.rs
@@ -37,6 +37,8 @@ macro_rules! debug {
     ($($args:tt)*) => { bun_output::scoped_log!(Redis, $($args)*) };
 }
 
+const MAX_READ_BUFFER_SIZE: usize = 16 * 1024 * 1024;
+
 /// Connection flags to track Valkey client state
 pub struct ConnectionFlags {
     // TODO(markovejnovic): I am not a huge fan of these flags. I would
@@ -689,6 +691,17 @@ impl ValkeyClient {
         any_socket_close(&socket);
     }
 
+    fn fail_read_buffer_too_large(&mut self) -> JsTerminated<()> {
+        self.flags.is_manually_closed = true;
+        self.read_buffer.clear_and_free();
+        self.fail(
+            b"Valkey response exceeded maximum read buffer size",
+            RedisError::InvalidResponse,
+        )?;
+        self.close();
+        Ok(())
+    }
+
     /// Handle connection closed event
     pub fn on_close(&mut self) -> JsTerminated<()> {
         self.unregister_auto_flusher();
@@ -785,6 +798,9 @@ impl ValkeyClient {
         );
         // Path 1: Buffer already has data, append and process from buffer
         if !self.read_buffer.remaining().is_empty() {
+            if (self.read_buffer.len() as usize).saturating_add(data.len()) > MAX_READ_BUFFER_SIZE {
+                return self.fail_read_buffer_too_large();
+            }
             self.read_buffer
                 .write(data)
                 .expect("failed to write to read buffer");
@@ -862,8 +878,12 @@ impl ValkeyClient {
                                 current_data_slice.len() - before_read_pos
                             );
                         }
+                        let remaining_stack_data = &current_data_slice[before_read_pos..];
+                        if remaining_stack_data.len() > MAX_READ_BUFFER_SIZE {
+                            return self.fail_read_buffer_too_large();
+                        }
                         self.read_buffer
-                            .write(&current_data_slice[before_read_pos..])
+                            .write(remaining_stack_data)
                             .expect("failed to write remaining stack data to buffer");
                         return Ok(()); // Exit onData, next call will use the buffer path
                     } else {
```