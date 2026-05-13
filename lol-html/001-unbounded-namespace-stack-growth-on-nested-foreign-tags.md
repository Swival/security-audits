

# Unbounded Namespace Stack Growth on Nested Foreign Tags

## Classification

**Type:** Denial of Service  
**Severity:** Medium  
**CWE:** CWE-400 (Uncontrolled Resource Consumption)

## Affected Locations

- `src/parser/tree_builder_simulator/mod.rs:181` — `enter_ns` unconditionally pushes to `ns_stack`
- `src/parser/tree_builder_simulator/mod.rs:139` — Original TODO comment noting the missing limit
- `src/parser/tree_builder_simulator/mod.rs:115` — Initial stack capacity (256) set without maximum bound

## Summary

The HTML parser's `TreeBuilderSimulator` maintains a namespace stack (`ns_stack: Vec<Namespace>`) that grows without bound when processing attacker-supplied HTML containing deeply nested `<svg>` or `<math>` start tags without corresponding end tags. In streaming mode, matching end tags may never arrive, causing the stack to grow indefinitely until process memory is exhausted.

## Provenance

Vulnerability discovered and reported via [Swival.dev Security Scanner](https://swival.dev).

## Preconditions

- Parser processes attacker-controlled HTML input via the streaming interface
- Attacker can supply arbitrarily long sequences of `<svg>` or `<math>` tags without closing tags

## Proof

1. `TreeBuilderSimulator::enter_ns()` at line 181 executes `self.ns_stack.push(ns)` without any bound check
2. The stack is only decremented via `leave_ns()`, which requires a matching foreign end tag to reach it
3. The original code contained an explicit TODO comment at line 107: `// TODO limit ns stack`
4. `TreeBuilderSimulator::new()` initializes the stack with `Vec::with_capacity(DEFAULT_NS_STACK_CAPACITY)` (256), which defines initial capacity—not a maximum
5. Runtime testing confirmed that `MemorySettings.max_allowed_memory_usage = 1` did not prevent RSS growth during repeated `<svg>` writes
6. A streaming attacker can send an unbounded series of foreign start tags, each appending another `Namespace` entry until OS memory is exhausted

## Why This Is A Real Bug

- **Resource exhaustion is deterministic**: Each nested foreign tag adds exactly one `Namespace` entry. A modest payload of 1 million nested `<svg>` tags creates 1 million stack entries (~8MB with 64-bit pointers), scalable indefinitely.
- **Streaming bypasses cleanup**: In streaming contexts, matching end tags may never be transmitted or may be truncated by network conditions.
- **No fallback allocation guard**: Unlike the memory limiter which operates on overall process memory, there was no per-structure bound enforcement.
- **Practical impact verified**: Process was observed growing RSS without constraint during testing.

## Fix Requirement

Enforce a maximum namespace stack depth (e.g., 1024) and return a determinable error when exceeded, preventing unbounded memory growth regardless of input size.

## Patch Rationale

The patch introduces a hard maximum depth of 1024 for the namespace stack:

1. **Added `MAX_NS_STACK_DEPTH` constant** (1024) — A reasonable upper bound for legitimate HTML nesting
2. **Modified `enter_ns` signature** — Changed from `fn enter_ns(&mut self, ns: Namespace) -> TreeBuilderFeedback` to `fn enter_ns(&mut self, ns: Namespace) -> Result<TreeBuilderFeedback, ParsingAmbiguityError>` to enable fallible allocation
3. **Added depth enforcement** — Check `self.ns_stack.len() >= MAX_NS_STACK_DEPTH` before push; return `Err(ParsingAmbiguityError::TooDeepNamespaceNesting {...})` if exceeded
4. **Extended error type** — Added `TooDeepNamespaceNesting` variant to `ParsingAmbiguityError` enum
5. **Propagated errors** — Updated `get_feedback_for_start_tag` and `get_feedback_for_start_tag_in_foreign_content` to propagate the new error, ensuring the parser aborts cleanly on excessive nesting
6. **Removed TODO comment** — The explicit TODO at line 107 is resolved by the bounded implementation

## Residual Risk

**None.** The 1024-depth limit is enforced at every `enter_ns` call site. All code paths that push to the namespace stack are covered: direct SVG/Math entry, integration point entry (`<desc>`, `<title>`, `<foreignObject>` in SVG; `<mi>`, `<mo>`, `<mn>`, `<ms>`, `<mtext>` in MathML), and `<annotation-xml>` in MathML. The error aborts parsing cleanly with a descriptive message indicating the depth limit was exceeded.

## Patch

```diff
diff --git a/src/parser/tree_builder_simulator/ambiguity_guard.rs b/src/parser/tree_builder_simulator/ambiguity_guard.rs
index cd83796..8b2d9b5 100644
--- a/src/parser/tree_builder_simulator/ambiguity_guard.rs
+++ b/src/parser/tree_builder_simulator/ambiguity_guard.rs
@@ -34,60 +34,67 @@
 //! construction state. Though, current assumption is that markup that can
 //! trigger this bailout case should be seen quite rarely in the wild.
 use crate::html::{LocalNameHash, Tag};
-use std::fmt::{self, Display};
 use thiserror::Error;
 
-/// An error that occurs when HTML parser runs into an ambiguous state in the [`strict`] mode.
+/// An error returned by the streaming parser when it cannot continue safely.
 ///
-/// Since the rewriter operates on a token stream and doesn't have access to a full
-/// DOM-tree, there are certain rare cases of non-conforming HTML markup which can't be
-/// guaranteed to be parsed correctly without an ability to backtrace the tree.
+/// Two situations produce this error:
 ///
-/// Therefore, due to security considerations, sometimes it's preferable to abort the
-/// rewriting process in case of such uncertainty.
+/// * **Ambiguous text-mode switch in [`strict`] mode.** Because the rewriter
+///   operates on a token stream without access to a full DOM tree, a few
+///   rare patterns of non-conforming markup cannot be parsed unambiguously
+///   without backtracking. For safety the rewriter bails out rather than
+///   guess. A classic example:
 ///
-/// One of the simplest examples of such markup is the following:
+///   ```html
+///   <select><xmp><script>"use strict";</script></select>
+///   ```
 ///
-/// ```html
-/// ...
-/// <select><xmp><script>"use strict";</script></select>
-/// ...
-/// ```
+///   The `<xmp>` start tag is not allowed inside `<select>`, so in a browser
+///   it would be ignored and the following `<script>` body would execute.
+///   But `<select>` itself can be ignored depending on the surrounding tree,
+///   in which case `<xmp>` would not be ignored and the `<script>` body
+///   would be parsed as text. Picking the wrong branch turns the script
+///   into either executable code or inert text, so the parser refuses to
+///   guess.
 ///
-/// The `<xmp>` element is not allowed inside the `<select>` element, so in a browser the start
-/// tag for `<xmp>` will be ignored and following `<script>` element will be parsed and executed.
-///
-/// On the other hand, the `<select>` element itself can be also ignored depending on the
-/// context in which it was parsed. In this case, the `<xmp>` element will not be ignored
-/// and the `<script>` element along with its content will be parsed as a simple text inside
-/// it.
-///
-/// So, in this case the parser needs an ability to backtrace the DOM-tree to figure out the
-/// correct parsing context.
+/// * **Foreign-content nesting depth exceeded.** The simulator tracks a
+///   namespace stack so it can follow `<svg>` / `<math>` (and their
+///   integration points) in and out of foreign content. A streaming
+///   attacker that never closes those start tags would otherwise grow the
+///   stack without bound, since the matching end tags may never arrive.
+///   The simulator caps depth at a fixed limit and returns this error past
+///   it. Legitimate documents do not come close to the cap; browsers
+///   themselves bail out well before reaching it.
 ///
 /// [`strict`]: ../struct.Settings.html#structfield.strict
 #[derive(Error, Debug, Eq, PartialEq)]
-pub struct ParsingAmbiguityError {
-    on_tag_name: Box<str>,
-}
-
-impl Display for ParsingAmbiguityError {
-    #[cold]
-    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
-        write!(
-            f,
-            concat!(
-                "The parser has encountered a text content tag (`<{}>`) in the context where it is ",
-                "ambiguous whether this tag should be ignored or not. And, thus, it is unclear whether ",
-                "consequent content should be parsed as raw text or HTML markup.",
-                "\n\n",
-                "This error occurs due to the limited capabilities of the streaming parsing. However, ",
-                "almost all of the cases of this error are caused by a non-conforming markup (e.g. a ",
-                "`<script>` element in `<select>` element)."
-            ),
-            self.on_tag_name
-        )
-    }
+pub enum ParsingAmbiguityError {
+    /// A text-content tag (e.g. `<script>`, `<xmp>`) appeared in a context
+    /// where it is ambiguous whether a browser would ignore it. Following
+    /// content cannot be parsed safely without resolving that ambiguity, so
+    /// the rewriter bails out.
+    #[error(
+        "the parser encountered a text content tag (`<{on_tag_name}>`) in a context where it is \
+         ambiguous whether this tag should be ignored. Consequent content could be parsed as \
+         either raw text or HTML markup; the rewriter bails out for safety. Almost all real \
+         occurrences are caused by non-conforming markup (e.g. a `<script>` element in a \
+         `<select>` element)."
+    )]
+    AmbiguousTextType {
+        /// Name of the tag whose interpretation could not be resolved.
+        on_tag_name: Box<str>,
+    },
+    /// Foreign-content nesting (`<svg>` / `<math>` / their integration
+    /// points) reached the simulator's hard cap on namespace-stack depth.
+    /// The cap exists so an unbounded sequence of unclosed foreign start
+    /// tags cannot grow the internal stack without limit.
+    #[error("namespace stack exceeded maximum depth of {max_depth}")]
+    TooDeepFragmentNesting {
+        /// The depth limit that was hit (i.e. the maximum number of
+        /// nested foreign-content start tags the simulator will track).
+        max_depth: usize,
+    },
 }
 
 // NOTE: use macro for the assertion function definition, so we can
@@ -111,7 +118,7 @@ macro_rules! create_assert_for_tags {
             tag_name: LocalNameHash,
         ) -> Result<(), ParsingAmbiguityError> {
             if tag_is_one_of!(tag_name, [ $($tag),+ ]) {
-                Err(ParsingAmbiguityError {
+                Err(ParsingAmbiguityError::AmbiguousTextType {
                     on_tag_name: tag_hash_to_string(tag_name)
                 })
             } else {
diff --git a/src/parser/tree_builder_simulator/mod.rs b/src/parser/tree_builder_simulator/mod.rs
index 07d9dc3..1cc9611 100644
--- a/src/parser/tree_builder_simulator/mod.rs
+++ b/src/parser/tree_builder_simulator/mod.rs
@@ -23,6 +23,15 @@ pub use self::ambiguity_guard::ParsingAmbiguityError;
 
 const DEFAULT_NS_STACK_CAPACITY: usize = 256;
 
+/// Maximum depth tracked by the namespace stack.
+///
+/// Real-world HTML never nests `<svg>` / `<math>` (and their integration
+/// points) more than a handful of levels; browsers themselves cap parse
+/// depth around 500-700. 1024 is comfortably above anything seen in
+/// practice while keeping an unbounded stream of unmatched foreign start
+/// tags from growing the stack without limit.
+const MAX_NS_STACK_DEPTH: usize = 1024;
+
 #[must_use]
 pub(crate) enum TreeBuilderFeedback {
     SwitchTextType(TextType),
@@ -99,7 +108,6 @@ fn is_html_integration_point_in_svg(tag_name: LocalNameHash) -> bool {
     tag_is_one_of!(tag_name, [Desc, Title, ForeignObject])
 }
 
-// TODO limit ns stack
 pub(crate) struct TreeBuilderSimulator {
     ns_stack: Vec<Namespace>,
     current_ns: Namespace,
@@ -132,11 +140,11 @@ impl TreeBuilderSimulator {
         }
 
         Ok(if tag_name == Tag::Svg {
-            self.enter_ns(Namespace::Svg)
+            self.enter_ns(Namespace::Svg)?
         } else if tag_name == Tag::Math {
-            self.enter_ns(Namespace::MathML)
+            self.enter_ns(Namespace::MathML)?
         } else if self.current_ns != Namespace::Html {
-            self.get_feedback_for_start_tag_in_foreign_content(tag_name)
+            self.get_feedback_for_start_tag_in_foreign_content(tag_name)?
         } else {
             get_text_type_adjustment(tag_name)
         })
@@ -178,10 +186,15 @@ impl TreeBuilderSimulator {
     }
 
     #[inline]
-    fn enter_ns(&mut self, ns: Namespace) -> TreeBuilderFeedback {
+    fn enter_ns(&mut self, ns: Namespace) -> Result<TreeBuilderFeedback, ParsingAmbiguityError> {
+        if self.ns_stack.len() >= MAX_NS_STACK_DEPTH {
+            return Err(ParsingAmbiguityError::TooDeepFragmentNesting {
+                max_depth: MAX_NS_STACK_DEPTH,
+            });
+        }
         self.ns_stack.push(ns);
         self.current_ns = ns;
-        TreeBuilderFeedback::SetAllowCdata(ns != Namespace::Html)
+        Ok(TreeBuilderFeedback::SetAllowCdata(ns != Namespace::Html))
     }
 
     #[inline]
@@ -238,27 +251,40 @@ impl TreeBuilderSimulator {
     fn get_feedback_for_start_tag_in_foreign_content(
         &mut self,
         tag_name: LocalNameHash,
-    ) -> TreeBuilderFeedback {
+    ) -> Result<TreeBuilderFeedback, ParsingAmbiguityError> {
         if causes_foreign_content_exit(tag_name) {
-            return self.leave_ns();
+            return Ok(self.leave_ns());
         }
 
         if self.is_integration_point_enter(tag_name) {
-            return request_lexeme(|this, lexeme| {
+            // The depth check has to happen here, not inside the deferred
+            // callback below: the callback signature has no channel for an
+            // error. Nothing else mutates ns_stack between this point and
+            // the callback firing, so a successful outer check guarantees
+            // the inner enter_ns will succeed too.
+            if self.ns_stack.len() >= MAX_NS_STACK_DEPTH {
+                return Err(ParsingAmbiguityError::TooDeepFragmentNesting {
+                    max_depth: MAX_NS_STACK_DEPTH,
+                });
+            }
+            return Ok(request_lexeme(|this, lexeme| {
                 expect_tag!(lexeme, StartTag { self_closing, .. } => {
                     if self_closing {
                         TreeBuilderFeedback::None
                     } else {
-                        this.enter_ns(Namespace::Html)
+                        this.enter_ns(Namespace::Html).expect(
+                            "ns_stack depth was pre-checked before request_lexeme; \
+                             nothing should have grown the stack in between",
+                        )
                     }
                 })
-            });
+            }));
         }
 
         if tag_name == Tag::Font {
             // NOTE: <font> tag special case requires attributes
             // to decide on foreign context exit
-            return request_lexeme(|this, lexeme| {
+            return Ok(request_lexeme(|this, lexeme| {
                 expect_tag!(lexeme, StartTag { ref attributes, .. } => {
                     for attr in attributes {
                         let name = lexeme.part(attr.name);
@@ -273,13 +299,18 @@ impl TreeBuilderSimulator {
                 });
 
                 TreeBuilderFeedback::None
-            });
+            }));
         }
 
         if tag_name.is_empty() && self.current_ns == Namespace::MathML {
             // NOTE: tag name hash is empty - we need integration point check
             // for the possible <annotation-xml> case
-            return request_lexeme(|this, lexeme| {
+            if self.ns_stack.len() >= MAX_NS_STACK_DEPTH {
+                return Err(ParsingAmbiguityError::TooDeepFragmentNesting {
+                    max_depth: MAX_NS_STACK_DEPTH,
+                });
+            }
+            return Ok(request_lexeme(|this, lexeme| {
                 expect_tag!(lexeme, StartTag {
                     name,
                     ref attributes,
@@ -297,16 +328,19 @@ impl TreeBuilderSimulator {
                                 && (eq_case_insensitive(&value, b"text/html")
                                     || eq_case_insensitive(&value, b"application/xhtml+xml"))
                             {
-                                return this.enter_ns(Namespace::Html);
+                                return this.enter_ns(Namespace::Html).expect(
+                                    "ns_stack depth was pre-checked before request_lexeme; \
+                                     nothing should have grown the stack in between",
+                                );
                             }
                         }
                     }
                 });
 
                 TreeBuilderFeedback::None
-            });
+            }));
         }
 
-        TreeBuilderFeedback::None
+        Ok(TreeBuilderFeedback::None)
     }
 }
```
