# Unmatched Emphasis Delimiters Cause Quadratic Parsing

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

`src/md/inlines.rs:556`

## Summary

`resolve_emphasis_delimiters` performed an unbounded backward opener search for every unmatched emphasis closer. Inputs containing many right-flanking delimiter runs with no possible opener forced each closer to rescan all prior delimiter runs, producing quadratic CPU cost while parsing a single markdown document.

The patch adds per-delimiter-class opener lower bounds so failed prefixes are not rescanned.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- A service parses attacker-controlled markdown.
- Emphasis parsing is enabled.
- The attacker can submit markdown containing many unmatched right-flanking emphasis delimiter runs.

## Proof

A payload made from repeated `a* ` segments creates many `*` delimiter runs where each delimiter is right-flanking and can close, but cannot open because it is followed by whitespace.

Parsing flow:

- `process_inline_content` calls `collect_emphasis_delimiters`.
- Each `*` in `a* ` becomes an `EmphDelim` with `can_close == true`, `can_open == false`, and `remaining > 0`.
- `process_inline_content` then calls `resolve_emphasis_delimiters`.
- For every closer, the old implementation initialized `oi = closer_idx` and decremented to zero looking for a matching opener.
- No prior delimiter could open, so `found_match` stayed false.
- The old implementation only deactivated the current closer and did not remember that the scanned prefix had no opener.

For `n` delimiter runs, closer `i` scans `i` previous runs, giving approximately `n(n-1)/2` failed checks before parsing completes.

## Why This Is A Real Bug

The behavior is reachable through normal markdown parsing because emphasis parsing is part of inline processing and is not gated by a disabling flag in `Flags`.

The attack requires only a single attacker-controlled markdown document. The parser performs CPU work proportional to the square of the number of delimiter runs before emitting output, making CPU exhaustion practical for services that parse untrusted markdown.

## Fix Requirement

The resolver must not repeatedly scan delimiter prefixes already proven to contain no valid opener for the current closer class.

A valid fix needs to maintain lower bounds or opener cache state keyed by the delimiter properties relevant to matching, and start future backward searches at that recorded bound instead of zero.

## Patch Rationale

The patch introduces `openers_bottom`, an array of lower bounds keyed by:

- delimiter character: `*`, `_`, or `~`
- delimiter count modulo 3
- whether the closer can also open

Before scanning backward, the resolver reads the lower bound for the current closer class and stops the search at that point. When no match is found, it records the current closer index as the new lower bound for that class.

This preserves matching behavior while preventing repeated failed scans over the same prefix. Unmatched closer-only delimiters are still deactivated as before.

## Residual Risk

None

## Patch

```diff
diff --git a/src/md/inlines.rs b/src/md/inlines.rs
index 0bd939f38e..58e251ea27 100644
--- a/src/md/inlines.rs
+++ b/src/md/inlines.rs
@@ -594,6 +594,17 @@ impl Parser<'_> {
             return;
         }
 
+        let opener_bottom_key = |d: &EmphDelim| -> usize {
+            let char_idx = match d.emph_char {
+                b'*' => 0,
+                b'_' => 1,
+                b'~' => 2,
+                _ => 0,
+            };
+            ((char_idx * 3) + (d.count % 3)) * 2 + (d.can_open as usize)
+        };
+        let mut openers_bottom: [usize; 18] = [0; 18];
+
         // Process potential closers from left to right
         let mut closer_idx: usize = 0;
         while closer_idx < len {
@@ -605,10 +616,11 @@ impl Parser<'_> {
             }
 
             // Look backward for a matching opener
+            let opener_bottom = openers_bottom[opener_bottom_key(&self.emph_delims[closer_idx])];
             let mut found_match = false;
-            if closer_idx > 0 {
+            if closer_idx > opener_bottom {
                 let mut oi: usize = closer_idx;
-                while oi > 0 {
+                while oi > opener_bottom {
                     oi -= 1;
                     if self.emph_delims[oi].emph_char != self.emph_delims[closer_idx].emph_char {
                         continue;
@@ -689,9 +701,12 @@ impl Parser<'_> {
                 }
             }
 
-            // If no match and can't open, deactivate
-            if !found_match && !self.emph_delims[closer_idx].can_open {
-                self.emph_delims[closer_idx].active = false;
+            // If no match, avoid rescanning the same failed prefix for this closer class.
+            if !found_match {
+                openers_bottom[opener_bottom_key(&self.emph_delims[closer_idx])] = closer_idx;
+                if !self.emph_delims[closer_idx].can_open {
+                    self.emph_delims[closer_idx].active = false;
+                }
             }
 
             closer_idx = closer_idx.wrapping_add(1);
```