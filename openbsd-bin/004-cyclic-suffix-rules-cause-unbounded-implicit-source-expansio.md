# cyclic suffix rules cause unbounded implicit-source expansion

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`make/suff.c:820`

## Summary

An attacker-controlled makefile can define cyclic suffix transformation rules that make implicit dependency search enqueue the same derived source states forever. When no generated source exists, `SuffFindThem` repeatedly expands suffix children through `SuffAddLevel`, causing unbounded CPU use and heap growth.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Victim runs `make` on an attacker-controlled makefile or repository.

## Proof

A malicious makefile defines cyclic suffix transformations, for example a `.b` to `.c` rule and a `.c` to `.b` rule, then requests a matching target such as `foo.a` without any existing generated source.

Observed expansion:

- `record_possible_suffixes` identifies `.a` on `foo.a` at `make/suff.c:1124`.
- `record_possible_suffix` seeds `srcs` with `foo.b` through `SuffAddLevel` at `make/suff.c:1099`.
- `SuffFindThem` dequeues each candidate at `make/suff.c:774`.
- `Targ_FindNode` and `Dir_FindFile` fail for the generated filename at `make/suff.c:782` and `make/suff.c:790`.
- `SuffFindThem` then calls `SuffAddLevel` again at `make/suff.c:803`.
- `SuffAddSrc` allocates a fresh `Src` and filename at `make/suff.c:658`, then appends it at `make/suff.c:666`.

With a `.b <-> .c` cycle, the queue alternates `foo.b -> foo.c -> foo.b -> ...`. Processed `Src` records are retained on `slst` at `make/suff.c:804`, so memory grows while the search spins.

## Why This Is A Real Bug

The suffix graph allows transformation cycles through `build_suffixes_graph`, and the implicit-source search does not record visited `(prefix, suffix)` states before the patch. Because missing generated files cause continued expansion, an attacker can force an infinite breadth-first dependency search using only makefile syntax. This is a practical denial of service against users who run `make` in untrusted repositories.

## Fix Requirement

Before enqueueing a new implicit source candidate, detect whether the same prefix and suffix already appear in the current parent chain. If so, do not allocate or enqueue another `Src`.

## Patch Rationale

The patch adds a cycle check at the start of `SuffAddSrc`. It walks from the current target `Src` through its parent chain and returns early if the candidate suffix and prefix already exist in that chain.

This prevents cyclic suffix rules from re-enqueueing the same state while preserving legitimate multi-stage transformations that do not revisit the same `(prefix, suffix)` pair.

## Residual Risk

None

## Patch

```diff
diff --git a/make/suff.c b/make/suff.c
index e9cab43..5f1d589 100644
--- a/make/suff.c
+++ b/make/suff.c
@@ -655,6 +655,10 @@ SuffAddSrc(
 
 	targ = ls->s;
 
+	for (s2 = targ; s2 != NULL; s2 = s2->parent)
+		if (s2->suff == s && strcmp(s2->prefix, targ->prefix) == 0)
+			return;
+
 	s2 = emalloc(sizeof(Src));
 	s2->file = Str_concat(targ->prefix, s->name, 0);
 	s2->prefix = targ->prefix;
```