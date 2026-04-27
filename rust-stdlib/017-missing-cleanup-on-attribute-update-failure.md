# Missing Cleanup On Attribute Update Failure

## Classification

Resource lifecycle bug; medium severity; confidence certain.

## Affected Locations

`library/std/src/os/windows/process.rs:695`

## Summary

`ProcThreadAttributeListBuilder::finish` initializes a Windows process-thread attribute list, then updates it with caller-provided attributes. If `UpdateProcThreadAttribute` fails after `InitializeProcThreadAttributeList` succeeds, `finish` returns early via `?` before constructing `ProcThreadAttributeList`. Because cleanup is only performed by `Drop for ProcThreadAttributeList`, the initialized list is not passed to `DeleteProcThreadAttributeList`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

`UpdateProcThreadAttribute` returns an error after `InitializeProcThreadAttributeList` succeeds.

## Proof

Attributes are accepted through `ProcThreadAttributeListBuilder::attribute` and `raw_attribute`, then processed in `finish`.

In the affected implementation:

- `finish` queries the required buffer size.
- `finish` allocates `attribute_list`.
- `finish` successfully calls `InitializeProcThreadAttributeList` on that buffer.
- `finish` loops over attributes and calls `UpdateProcThreadAttribute`.
- On `sys::cvt(...)?` failure, `finish` returns early.
- The buffer has not yet been wrapped in `ProcThreadAttributeList`.
- `Drop for ProcThreadAttributeList` is therefore never reached.
- The only committed-source cleanup call to `DeleteProcThreadAttributeList` is in `Drop for ProcThreadAttributeList`.

The failure path is reachable because callers can provide raw attribute keys through the public builder API, and invalid or unsupported keys can cause `UpdateProcThreadAttribute` to fail.

## Why This Is A Real Bug

Windows requires a successfully initialized process-thread attribute list to be cleaned up with `DeleteProcThreadAttributeList`. The code only performs that cleanup from `ProcThreadAttributeList::drop`. Since the initialized buffer is not wrapped until after all updates succeed, any update failure skips the destructor and leaves initialized Windows attribute-list state unfinalized. Repeated failing constructions can leak or retain resources on that error path.

## Fix Requirement

After successful `InitializeProcThreadAttributeList`, the initialized buffer must be owned by a guard that calls `DeleteProcThreadAttributeList` if any later operation returns early.

## Patch Rationale

The patch wraps the initialized buffer in `ProcThreadAttributeList` immediately after `InitializeProcThreadAttributeList` succeeds and before the `UpdateProcThreadAttribute` loop.

This makes the existing `Drop for ProcThreadAttributeList` act as the required cleanup guard:

- If any `UpdateProcThreadAttribute` call fails, `?` returns early and drops `attribute_list`.
- Dropping `attribute_list` calls `DeleteProcThreadAttributeList`.
- If all updates succeed, the fully initialized `ProcThreadAttributeList` is returned normally.
- No separate guard type is needed because the existing RAII type already has the correct cleanup behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/os/windows/process.rs b/library/std/src/os/windows/process.rs
index ff3ae8145e0..6eaad185b81 100644
--- a/library/std/src/os/windows/process.rs
+++ b/library/std/src/os/windows/process.rs
@@ -689,6 +689,9 @@ pub fn finish(&self) -> io::Result<ProcThreadAttributeList<'a>> {
             )
         })?;
 
+        let mut attribute_list =
+            ProcThreadAttributeList { attribute_list, _lifetime_marker: marker::PhantomData };
+
         // # Add our attributes to the buffer.
         // It's theoretically possible for the attribute count to exceed a u32
         // value. Therefore, we ensure that we don't add more attributes than
@@ -696,7 +699,7 @@ pub fn finish(&self) -> io::Result<ProcThreadAttributeList<'a>> {
         for (&attribute, value) in self.attributes.iter().take(attribute_count as usize) {
             sys::cvt(unsafe {
                 sys::c::UpdateProcThreadAttribute(
-                    attribute_list.as_mut_ptr().cast::<c_void>(),
+                    attribute_list.attribute_list.as_mut_ptr().cast::<c_void>(),
                     0,
                     attribute,
                     value.ptr,
@@ -707,7 +710,7 @@ pub fn finish(&self) -> io::Result<ProcThreadAttributeList<'a>> {
             })?;
         }
 
-        Ok(ProcThreadAttributeList { attribute_list, _lifetime_marker: marker::PhantomData })
+        Ok(attribute_list)
     }
 }
```