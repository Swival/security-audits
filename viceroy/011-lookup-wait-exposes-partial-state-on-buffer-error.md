# lookup_wait exposes partial state on buffer error

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/wiggle_abi/kv_store_impl.rs:73`

## Summary
`lookup_wait` commits guest-visible outputs before validating that the caller-provided metadata buffer is large enough. On a successful lookup with metadata longer than `metadata_buf_len`, the function inserts the body handle, writes `body_handle_out`, and writes `nwritten_out = metadata_len`, then returns `BufferLengthError`. This exposes partial success state on an error path and violates all-or-nothing hostcall behavior.

## Provenance
- Verified finding reproduced from supplied report and reproducer summary
- Reference scanner: https://swival.dev

## Preconditions
- Successful KV lookup returns `Some(value)`
- Returned metadata length exceeds caller-supplied `metadata_buf_len`

## Proof
In the `Ok(Some(value))` path of `lookup_wait`, untrusted guest-controlled outputs are updated before buffer validation:
- A live body is inserted into the session and its handle is written to `body_handle_out`
- `nwritten_out` is set to the metadata length
- Only afterward does the code compare `meta_len_u32` against `metadata_buf_len`
- If metadata is too large, the function returns `types::Error::BufferLengthError`

Because that return occurs after the handle insertion and output writes, the guest observes a failed call that still leaks a valid body handle and the metadata length, while later outputs such as `generation_out` and `kv_error_out` are not committed. The reproducer confirms this path is reachable whenever an existing item has oversized metadata.

## Why This Is A Real Bug
This is externally observable inconsistent state, not a theoretical cleanup issue:
- The hostcall reports failure but still hands out a consumable body handle
- Callers that assume failed calls produce no outputs can leak or misuse that handle
- The pending lookup is already consumed, so the operation cannot simply be retried unchanged
- Comparable component-ABI code validates metadata before returning the body, showing the intended atomic ordering

## Fix Requirement
Validate metadata length before any guest writes or body insertion. Only commit `body_handle_out`, `nwritten_out`, metadata bytes, and related outputs after all fallible preconditions for success have passed.

## Patch Rationale
The patch in `011-lookup-wait-exposes-partial-state-on-buffer-error.patch` reorders `lookup_wait` so metadata size is checked first, before inserting the body or writing any guest outputs. This restores atomic success semantics for the `Ok(Some(value))` path: oversized metadata now returns `BufferLengthError` without exposing a body handle or partially updated output state.

## Residual Risk
None

## Patch
```diff
diff --git a/src/wiggle_abi/kv_store_impl.rs b/src/wiggle_abi/kv_store_impl.rs
index 7f3d8b1..c2a91d4 100644
--- a/src/wiggle_abi/kv_store_impl.rs
+++ b/src/wiggle_abi/kv_store_impl.rs
@@ -70,17 +70,17 @@ impl KvStore for Session {
                 Ok(None) => {
                     kv_error_out.write(types::KvError::Ok)?;
                 }
-                Ok(Some(value)) => {
-                    let body_handle = self.insert_body(value.body);
-                    body_handle_out.write(body_handle.into())?;
-
+                Ok(Some(value)) => {
                     let meta_len_u32 = u32::try_from(value.metadata.len())
                         .map_err(|_| types::Error::BufferLengthError)?;
-                    nwritten_out.write(meta_len_u32)?;
 
                     if meta_len_u32 > metadata_buf_len {
                         return Err(types::Error::BufferLengthError.into());
                     }
 
+                    let body_handle = self.insert_body(value.body);
+                    body_handle_out.write(body_handle.into())?;
+                    nwritten_out.write(meta_len_u32)?;
+
                     let metadata = metadata_buf
                         .as_array(meta_len_u32)
                         .as_slice_mut()?;
```