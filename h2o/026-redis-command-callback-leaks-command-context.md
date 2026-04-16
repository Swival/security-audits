# Redis command callback retains native command context until GC

## Classification
- Type: resource lifecycle bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/handler/mruby/redis.c:191`

## Summary
- Completed Redis command callbacks unregister the MRuby wrapper object but do not immediately dispose the native `command_ctx`.
- Native memory is therefore retained until a later MRuby GC sweep runs `on_gc_dispose_command`.
- Repeated completed commands can accumulate native heap usage proportional to finished command count before GC.

## Provenance
- Verified from reproduced behavior and source inspection.
- Scanner: https://swival.dev

## Preconditions
- Issue Redis commands repeatedly before MRuby garbage collection runs.

## Proof
- `call_method` allocates a `command_ctx`, stores it in `ctx->refs.command`, and registers that wrapper with MRuby GC.
- `on_redis_command` delivers the reply and calls `mrb_gc_unregister` for `ctx->refs.command`, but it does not free `command_ctx` or clear the wrapped pointer.
- The remaining disposal path is `on_gc_dispose_command`, which is only invoked later during MRuby garbage collection.
- MRuby GC behavior in `deps/mruby/src/gc.c:571` and `deps/mruby/src/gc.c:1296` confirms reclamation is deferred, not immediate.
- As a result, each completed command retains one native `command_ctx` until GC, causing native heap growth under sustained command traffic.

## Why This Is A Real Bug
- This is not just delayed Ruby object reclamation; the retained allocation is native heap owned by the MRuby Redis bridge.
- Reply completion is the terminal lifecycle event for one-shot command state, so keeping `command_ctx` alive after callback completion is unnecessary retention.
- The H2O Redis layer frees only its own `h2o_redis_command_t`; it does not release the MRuby-side `command_ctx`.
- Under repeated command execution before GC, memory usage grows with workload, matching a real resource lifecycle defect.

## Fix Requirement
- Dispose the native `command_ctx` when reply delivery finishes, or clear `DATA_PTR` and explicitly invoke the same cleanup path immediately.
- Ensure later MRuby GC disposal becomes a no-op to avoid double free.

## Patch Rationale
- The patch updates `on_redis_command` in `lib/handler/mruby/redis.c` to immediately release the native command context after reply delivery.
- It clears the wrapped `DATA_PTR` before unregistering or final disposal so that any later `on_gc_dispose_command` call cannot free the same context twice.
- This aligns native resource lifetime with command completion rather than deferred garbage collection.

## Residual Risk
- None

## Patch
- Patch file: `026-redis-command-callback-leaks-command-context.patch`