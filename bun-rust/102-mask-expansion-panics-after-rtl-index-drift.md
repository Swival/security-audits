# mask expansion panics after RTL index drift

## Classification

Denial of service, medium severity, confidence certain.

## Affected Locations

`src/css/properties/transition.rs:474`

## Summary

`TransitionHandler::flush` expands attacker-controlled `transition-property` lists through `expand_properties`. When logical property compilation and WebKit mask prefixing are enabled, an inline logical property can create an RTL property list, then a later WebKit mask expansion increments the shared LTR loop index before the RTL list is updated. The subsequent RTL access uses the incremented index and can panic out of bounds, aborting CSS compilation.

## Provenance

Verified from the supplied reproduced finding and patch. Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Logical compilation is enabled.
- WebKit mask prefixing is enabled.
- A lower-privileged developer or other CSS source supplier can provide CSS that reaches the Rust CSS compilation/minification worker.
- The `transition-property` list places an inline logical property before a WebKit mask property such as `mask-border-source`.

## Proof

A minimal trigger shape is:

```css
transition-property: inline-size, mask-border-source;
```

Execution path:

- `transition-property` reaches `TransitionHandler::flush`, which calls `expand_properties` on the attacker-controlled property list.
- `inline-size` is an inline logical property, so `expand_properties` creates `rtl_properties` from the current list and replaces index `0` in LTR and RTL independently.
- The loop advances `i` to `1`.
- At index `1`, `mask-border-source` maps through `masking::get_webkit_mask_property` to a WebKit mask-box-image property.
- The vulnerable code inserts the WebKit property into the LTR list at `i`, then increments `i` to `2`.
- It then indexes `rtl_props.slice_mut()[i as usize]` using `i == 2`.
- The RTL list was not extended in the same step, and for the two-item trigger list its length remains `2`, so index `2` is out of bounds.
- Rust panics on the bounds check, aborting the CSS compilation worker.

## Why This Is A Real Bug

The property list is attacker-controlled CSS input, and the failure is deterministic under the stated target settings. The panic is not a rejected parse or recoverable compilation error; it is a Rust bounds panic caused by inconsistent mutation/indexing between the LTR and RTL property lists. This can terminate the CSS compilation worker and produce denial of service.

## Fix Requirement

The RTL list must be updated using the original loop index for the current source property, not the post-LTR-insertion index. LTR and RTL insertions must not share a drifted index that can exceed one list’s length.

## Patch Rationale

The patch captures the current loop position in `index` before any mask expansion mutates `i`.

- LTR prefixing and WebKit mask lookup use `properties.at(index)`.
- LTR insertion still increments `i` to account for the extra inserted LTR property.
- RTL prefixing and WebKit mask lookup use `rtl_props` at `index`, the matching original position.
- RTL insertion uses `index` and does not additionally increment `i`, avoiding double advancement and preventing out-of-bounds access.

This preserves the loop’s LTR expansion behavior while keeping RTL access aligned to the corresponding pre-increment element.

## Residual Risk

None

## Patch

```diff
diff --git a/src/css/properties/transition.rs b/src/css/properties/transition.rs
index ec9f783343..6da0d76377 100644
--- a/src/css/properties/transition.rs
+++ b/src/css/properties/transition.rs
@@ -574,30 +574,31 @@ mod transition_handler_body {
                     properties.slice_mut()[i as usize].set_prefixes_for_targets(context.targets);
 
                     // Expand mask properties, which use different vendor-prefixed names.
-                    if let Some(property_id) = masking::get_webkit_mask_property(properties.at(i)) {
+                    let index = i;
+                    if let Some(property_id) = masking::get_webkit_mask_property(properties.at(index)) {
                         if context
                             .targets
                             .prefixes(VendorPrefix::NONE, Feature::MaskBorder)
                             .contains(VendorPrefix::WEBKIT)
                         {
-                            properties.insert(i, property_id);
+                            properties.insert(index, property_id);
                             i += 1;
                         }
                     }
 
                     if let Some(rtl_props) = &mut rtl_properties {
-                        rtl_props.slice_mut()[i as usize].set_prefixes_for_targets(context.targets);
+                        rtl_props.slice_mut()[index as usize]
+                            .set_prefixes_for_targets(context.targets);
 
                         if let Some(property_id) =
-                            masking::get_webkit_mask_property(rtl_props.at(i))
+                            masking::get_webkit_mask_property(rtl_props.at(index))
                         {
                             if context
                                 .targets
                                 .prefixes(VendorPrefix::NONE, Feature::MaskBorder)
                                 .contains(VendorPrefix::WEBKIT)
                             {
-                                rtl_props.insert(i, property_id);
-                                i += 1;
+                                rtl_props.insert(index, property_id);
                             }
                         }
                     }
```