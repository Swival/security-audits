# Receiver removal shifts array the wrong direction

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/handler/status.c:187`

## Summary
`on_context_dispose` removes a receiver from `self->receivers`, but its `memmove` shifts entries in the wrong direction. When the removed receiver is not the last element, the surviving tail is copied from index `i` into `i + 1` instead of from `i + 1` into `i`. This corrupts the receiver list during normal context teardown and can later route status messages through a stale receiver pointer.

## Provenance
- Verified from the provided reproducer and source review
- Scanner reference: https://swival.dev

## Preconditions
- Disposing a context while at least one later receiver remains in `self->receivers`

## Proof
In `lib/handler/status.c:187`, the removal path executes:
```c
memmove(self->receivers.entries + i + 1, self->receivers.entries + i, self->receivers.size - i - 1);
```

For vector removal, survivors after the removed element must shift left into slot `i`. The current call instead shifts the range starting at `i` one slot right.

Example with receivers `[A, B, C]` and removing `B` at `i = 1`:
- Current code copies one element from slot `1` to slot `2`
- Array becomes `[A, B, B]`
- Size is then decremented to `2`
- Logical contents become `[A, B]`, so the removed receiver remains and the surviving receiver `C` is lost

A later status broadcast iterates `self->receivers.entries` and calls `h2o_multithread_send_message(...)` on the stale entry in `lib/handler/status.c:189`. The reproducer shows that the disposed context unregisters and frees the associated status state before this later send, making the stale pointer reachable and dangerous.

## Why This Is A Real Bug
This is a direct, source-grounded removal bug in a live teardown path. It does not depend on undefined external state: creating multiple contexts, disposing a non-terminal one, and then issuing another status request is sufficient. The stale receiver pointer can then be dereferenced by `h2o_multithread_send_message`, after the disposed context has already unregistered and freed related state, yielding use-after-free style corruption or a crash.

## Fix Requirement
Replace the `memmove` arguments so entries after the removed index are shifted left from `i + 1` into `i`.

## Patch Rationale
The patch makes the removal operation match vector semantics: copy the tail over the removed slot, then decrement `size`. This preserves all surviving receivers in order and removes the stale pointer from the active prefix.

## Residual Risk
None

## Patch
```diff
diff --git a/lib/handler/status.c b/lib/handler/status.c
index 615531d..ab3a7c0 100644
--- a/lib/handler/status.c
+++ b/lib/handler/status.c
@@ -184,7 +184,7 @@ static void on_context_dispose(h2o_handler_t *_self, h2o_context_t *ctx)
     size_t i;
     for (i = 0; i != self->receivers.size; ++i)
         if (self->receivers.entries[i] == &status_ctx->receiver) {
-            memmove(self->receivers.entries + i + 1, self->receivers.entries + i, self->receivers.size - i - 1);
+            memmove(self->receivers.entries + i, self->receivers.entries + i + 1, sizeof(*self->receivers.entries) * (self->receivers.size - i - 1));
             break;
         }
     assert(i != self->receivers.size);
```