# Streaming Redis channel never marks unsubscribe state

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/handler/mruby/embedded.c.h:366`

## Summary
`H2O::Redis::Command::Streaming::Channel#shift` advertises EOF with `return nil if @replies.empty? && @unsubscribed`, but on an `unsubscribe` reply it returned `nil` without first setting `@unsubscribed = true`. A later `shift` call on the same channel can therefore miss the EOF guard and block waiting for a reply that will never arrive.

## Provenance
- Verified from the provided finding and reproducer against the checked source
- Scanner reference: https://swival.dev

## Preconditions
- A streaming Redis channel receives an `unsubscribe` reply
- Caller invokes `shift` again after that unsubscribe reply

## Proof
- In `lib/handler/mruby/embedded.c.h:366`, `shift` first checks `return nil if @replies.empty? && @unsubscribed`
- Replies arrive through `_h2o__redis_join_reply(@command)` or `@replies.shift`, so unsubscribe acknowledgements are processed by this method
- When `kind == 'unsubscribe'`, the method returned `nil` immediately and did not set `@unsubscribed = true`
- After consuming that unsubscribe reply, the queue is empty but `@unsubscribed` remains false
- A subsequent `shift` call therefore bypasses the EOF guard and waits for another reply on a finalized subscription command
- The reproducer confirms this second post-unsubscribe `shift` blocks until an unrelated disconnect or error resumes it

## Why This Is A Real Bug
This is a behavioral bug, not a cosmetic state mismatch. The method’s own contract encodes terminal state with `@unsubscribed`, and callers may legitimately invoke `shift` again to observe stable EOF semantics. Failing to persist unsubscribe state makes termination non-idempotent and can hang request processing because subscribe commands do not arm the normal Redis command timeout path.

## Fix Requirement
Set `@unsubscribed = true` before returning `nil` for an `unsubscribe` reply so future `shift` calls immediately observe terminal state.

## Patch Rationale
The patch updates the unsubscribe branch in `lib/handler/mruby/embedded.c.h` to record the terminal unsubscribe state before returning. This preserves existing behavior for the first unsubscribe reply while making subsequent `shift` calls correctly return EOF instead of blocking.

## Residual Risk
None

## Patch
- Patch file: `001-streaming-redis-channel-never-marks-unsubscribe-state.patch`
- Change: set `@unsubscribed = true` in the `kind == 'unsubscribe'` branch before `return nil`
- Effect: post-unsubscribe `shift` calls satisfy the existing EOF guard and no longer block on an already-terminated stream