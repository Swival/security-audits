# Peer Max Frame Size Zero Causes Continuation Loop

## Classification

Denial of service, high severity, certain confidence.

## Affected Locations

`src/runtime/api/bun/h2_frame_parser.rs:3569`

## Summary

A malicious HTTP/2 peer can advertise `SETTINGS_MAX_FRAME_SIZE=0`. The parser stores that invalid value without RFC range validation, and later outbound header/trailer fragmentation uses it as the continuation chunk size. For any nonempty encoded header block that requires CONTINUATION handling, the loop writes zero-byte chunks and never advances, blocking the runtime thread.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The parser accepts remote HTTP/2 SETTINGS frames.
- `SETTINGS_MAX_FRAME_SIZE` from the peer is stored without validating the RFC 7540 range `16384..=0xFFFFFF`.
- Local code later sends nonempty request headers or trailers using `remote_settings.max_frame_size`.

## Proof

The remote SETTINGS handler parses each `SettingsPayloadUnit` and calls `remote_settings.update_with(unit)` without validating `SETTINGS_MAX_FRAME_SIZE`.

When the attacker supplies `SETTINGS_MAX_FRAME_SIZE=0`, later send paths derive:

- `actual_max_frame_size` from `remote_settings.max_frame_size`.
- `first_chunk_size = actual_max_frame_size`.
- In the continuation loop, `chunk_size = remaining.min(actual_max_frame_size)`.

With `actual_max_frame_size == 0`, `chunk_size` is always `0`. The writer emits an empty slice, then `offset += chunk_size` leaves `offset` unchanged. Because `offset < encoded_size` remains true for nonempty encoded headers, the loop never terminates.

The reproduced paths are:

- Request header CONTINUATION path using `actual_max_frame_size` at `src/runtime/api/bun/h2_frame_parser.rs:6990`, zero `first_chunk_size` at `src/runtime/api/bun/h2_frame_parser.rs:7080`, and non-advancing `offset += chunk_size` at `src/runtime/api/bun/h2_frame_parser.rs:7112`.
- Trailer CONTINUATION path using `actual_max_frame_size` at `src/runtime/api/bun/h2_frame_parser.rs:6070` and zero-sized continuation chunks at `src/runtime/api/bun/h2_frame_parser.rs:6112`.

## Why This Is A Real Bug

HTTP/2 peers control their SETTINGS frames. A malicious peer can send `SETTINGS_MAX_FRAME_SIZE=0`, then cause normal local behavior to send nonempty headers or trailers. The affected continuation loop is synchronous and non-progressing, so it can pin the runtime thread indefinitely. The impact is attacker-triggered denial of service.

## Fix Requirement

Reject remote `SETTINGS_MAX_FRAME_SIZE` values outside `16384..=0xFFFFFF` before storing them in `remote_settings`.

## Patch Rationale

The patch validates each parsed remote settings unit before `remote_settings.update_with(unit)`. If the unit is `SETTINGS_MAX_FRAME_SIZE` and the value is below `16384` or above `MAX_FRAME_SIZE`, the parser resets the read buffer, sends a GOAWAY with `PROTOCOL_ERROR`, and returns without storing the invalid value. This prevents zero or otherwise invalid peer frame sizes from reaching outbound fragmentation logic.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/api/bun/h2_frame_parser.rs b/src/runtime/api/bun/h2_frame_parser.rs
index a8e77641e7..fa31e982e3 100644
--- a/src/runtime/api/bun/h2_frame_parser.rs
+++ b/src/runtime/api/bun/h2_frame_parser.rs
@@ -4343,9 +4343,23 @@ impl H2FrameParser {
                 self.remote_settings.get().unwrap_or_default();
             let mut i: usize = 0;
             let payload = content.data();
+            let end = content.end;
             while i < payload.len() {
                 let mut unit = SettingsPayloadUnit::default();
                 SettingsPayloadUnit::from::<true>(&mut unit, &payload[i..i + setting_byte_size], 0);
+                if SettingsType(unit.type_) == SettingsType::SETTINGS_MAX_FRAME_SIZE
+                    && (unit.value < 16384 || unit.value > MAX_FRAME_SIZE)
+                {
+                    self.read_buffer.with_mut(|rb| rb.reset());
+                    self.send_go_away(
+                        frame.stream_identifier,
+                        ErrorCode::PROTOCOL_ERROR,
+                        b"Invalid SETTINGS_MAX_FRAME_SIZE",
+                        self.last_stream_id.get(),
+                        true,
+                    );
+                    return end;
+                }
                 remote_settings.update_with(unit);
                 let (_ut, _uv) = (unit.type_, unit.value);
                 bun_output::scoped_log!(
@@ -4357,7 +4371,6 @@ impl H2FrameParser {
                 );
                 i += setting_byte_size;
             }
-            let end = content.end;
             self.read_buffer.with_mut(|rb| rb.reset());
             self.remote_settings.set(Some(remote_settings));
             let _iws = remote_settings.initial_window_size;
```