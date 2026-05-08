# Capped Crosslinks Are Iterated Past Storage

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.bin/infocmp/infocmp.c:1070`

`usr.bin/infocmp/infocmp.c:1074`

`usr.bin/infocmp/infocmp.c:1090`

`usr.bin/infocmp/infocmp.c:1093`

`usr.bin/infocmp/infocmp.c:1105`

## Summary

`infocmp -F` stores crosslink pointers only while `ncrosslinks < MAX_CROSSLINKS`, but increments `ncrosslinks` unconditionally. Later report loops iterate to `ncrosslinks` and dereference `crosslinks[i]`. If attacker-controlled compared terminfo source files create more matches than the fixed `crosslinks` array can store, `infocmp` reads past the array and can crash.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Victim runs `infocmp -F` comparison on attacker-controlled terminfo source files.

## Proof

In `file_comparison`, the matching loop stores crosslink pointers conditionally:

```c
if (qp->ncrosslinks < MAX_CROSSLINKS)
    qp->crosslinks[qp->ncrosslinks] = rp;
qp->ncrosslinks++;

if (rp->ncrosslinks < MAX_CROSSLINKS)
    rp->crosslinks[rp->ncrosslinks] = qp;
rp->ncrosslinks++;
```

The counters can therefore exceed the number of valid stored pointers.

The later reporting loop trusts the inflated count:

```c
for (i = 0; i < qp->ncrosslinks; i++)
    _nc_first_name((qp->crosslinks[i])->tterm.term_names);
```

The symmetric loop for file 2 has the same behavior.

A practical trigger is one file-1 entry with more than `MAX_CROSSLINKS` aliases, for example `foo|a1|...|a17`, and file-2 entries named `a1` through `a17`. This creates more matches than the fixed array stores while avoiding same-file duplicate-name cleanup.

With equivalent `infocmp -F -d f1 f2` input, the process printed the first 16 stored matches and then segfaulted when dereferencing `crosslinks[16]`, which is past the fixed array.

## Why This Is A Real Bug

The array write is capped, but the count used for later reads is not. The value controlling the read loop is derived from attacker-controlled terminfo names and aliases. Once more than `MAX_CROSSLINKS` matches are created, the program dereferences uninitialized or out-of-bounds pointer storage and terminates. This is deterministic denial of service for victims comparing untrusted source files.

## Fix Requirement

All reads from `crosslinks[]` must be bounded by the number of pointers actually stored. The implementation must either cap `ncrosslinks` at `MAX_CROSSLINKS` or keep the existing total-match count and cap every array iteration to `MAX_CROSSLINKS`.

## Patch Rationale

The patch bounds both reporting loops by `MAX_CROSSLINKS` while preserving the existing `ncrosslinks` value used in diagnostic messages. This keeps the visible total match count intact and prevents dereferencing entries that were never stored in the fixed-size `crosslinks` array.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/infocmp/infocmp.c b/usr.bin/infocmp/infocmp.c
index e23b729..2de91d3 100644
--- a/usr.bin/infocmp/infocmp.c
+++ b/usr.bin/infocmp/infocmp.c
@@ -1087,7 +1087,7 @@ file_comparison(int argc, char *argv[])
 			   argv[0],
 			   qp->ncrosslinks,
 			   argv[1]);
-	    for (i = 0; i < qp->ncrosslinks; i++)
+	    for (i = 0; i < qp->ncrosslinks && i < MAX_CROSSLINKS; i++)
 		(void) fprintf(stderr,
 			       "\t%s\n",
 			       _nc_first_name((qp->crosslinks[i])->tterm.term_names));
@@ -1102,7 +1102,7 @@ file_comparison(int argc, char *argv[])
 			   argv[1],
 			   rp->ncrosslinks,
 			   argv[0]);
-	    for (i = 0; i < rp->ncrosslinks; i++)
+	    for (i = 0; i < rp->ncrosslinks && i < MAX_CROSSLINKS; i++)
 		(void) fprintf(stderr,
 			       "\t%s\n",
 			       _nc_first_name((rp->crosslinks[i])->tterm.term_names));
```