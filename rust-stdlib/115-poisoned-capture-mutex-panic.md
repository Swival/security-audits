# Poisoned Capture Mutex Panic

## Classification

error-handling bug; medium severity; confidence certain.

## Affected Locations

`library/test/src/bench.rs:233`

## Summary

Benchmark output capture uses `Arc<Mutex<Vec<u8>>>` and reports captured stdout after `catch_unwind`. If benchmark execution poisons that mutex, result reporting calls `data.lock().unwrap()` and panics instead of emitting the expected `CompletedTest`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Benchmark output capture is enabled with `nocapture == false`.
- The benchmark panics while the output capture mutex is held.
- The capture mutex becomes poisoned before benchmark result reporting.

## Proof

The benchmark harness creates captured output storage as:

```rust
let data = Arc::new(Mutex::new(Vec::new()));
```

When capture is enabled, the same mutex is installed for stdout capture:

```rust
io::set_output_capture(Some(data.clone()));
```

Benchmark execution is wrapped with:

```rust
let result = catch_unwind(AssertUnwindSafe(|| bs.bench(f)));
```

This converts benchmark panics into `TestResult::TrFailed`. However, reporting then unconditionally reads captured output with:

```rust
let stdout = data.lock().unwrap().to_vec();
```

The reproducer confirmed that `std::io::set_output_capture` writes through a locked capture buffer, and formatting during `println!` can invoke user `Display` code while that lock is held. If the `Display` implementation panics, unwinding poisons the capture mutex. After `catch_unwind`, `data.is_poisoned()` is true, and the final `data.lock().unwrap()` panics with `PoisonError`.

## Why This Is A Real Bug

The benchmark harness intentionally catches benchmark panics and maps them to `TestResult::TrFailed`. A poisoned capture mutex is a reachable consequence of such a panic while captured output is being formatted. The later `unwrap()` violates the harness error-handling path by causing a second panic during reporting, preventing the intended `CompletedTest` from being sent.

## Fix Requirement

Handle `PoisonError` when reading the captured output buffer. The harness should recover the inner buffer or otherwise report failure without panicking.

## Patch Rationale

The patch changes the final capture-buffer read from panicking on poison to recovering the inner `Vec<u8>`:

```rust
let stdout = data.lock().unwrap_or_else(|err| err.into_inner()).to_vec();
```

This mirrors the appropriate recovery behavior for output capture: even if a panic poisoned the mutex, the buffer remains available and can be included in the `CompletedTest`. The existing `TestResult::TrFailed` classification is preserved.

## Residual Risk

None

## Patch

```diff
diff --git a/library/test/src/bench.rs b/library/test/src/bench.rs
index 62e51026b81..a0a62960a46 100644
--- a/library/test/src/bench.rs
+++ b/library/test/src/bench.rs
@@ -230,7 +230,7 @@ pub fn benchmark<F>(
         Ok(Err(_)) => TestResult::TrFailed,
     };
 
-    let stdout = data.lock().unwrap().to_vec();
+    let stdout = data.lock().unwrap_or_else(|err| err.into_inner()).to_vec();
     let message = CompletedTest::new(id, desc, test_result, None, stdout);
     monitor_ch.send(message).unwrap();
 }
```