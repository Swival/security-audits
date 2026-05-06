# Empty Global Substitution Never Advances

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`make/varmodifiers.c:573`

## Summary

An attacker-controlled `:S` variable modifier with an empty left-hand side and the `g` flag can make `make` loop indefinitely during variable expansion. The unanchored global substitution path repeatedly matches the same zero-length position, optionally appending replacement text forever and consuming CPU and memory.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

`make` expands an attacker-controlled variable modifier.

## Proof

A modifier of the form `:S///g` or `:S//replacement/g` is accepted by `common_get_patternarg`.

The parser permits:

- Empty `lhs`, because an immediate delimiter produces `pattern->leftLen == 0`.
- Global substitution, because trailing `g` sets `VAR_SUB_GLOBAL`.
- Unanchored substitution, because neither `VAR_MATCH_START` nor `VAR_MATCH_END` is set.

Execution then reaches `VarSubstitute` through `VarModifiers_Apply` and `VarModify`. In the unanchored substitution loop:

- `strstr(word->s, pattern->lhs)` with an empty `lhs` returns `word->s`.
- `Buf_AddChars(buf, pattern->rightLen, pattern->rhs)` appends the replacement.
- `wordLen -= (cp - word->s) + pattern->leftLen` leaves `wordLen` unchanged because both terms are zero.
- `word->s = cp + pattern->leftLen` reassigns `word->s` to the same pointer.
- `done` is not set because `wordLen != 0` and `VAR_SUB_GLOBAL` is set.

With a nonempty replacement, memory grows without bound. With an empty replacement, the process spins indefinitely.

## Why This Is A Real Bug

The code accepts a syntactically valid attacker-controlled modifier that creates a zero-length global match in a loop that only terminates when input advances, the word length reaches zero, or global substitution is disabled. None of those conditions occurs for an unanchored empty `:S` pattern with `g`, so the behavior is deterministic denial of service during variable expansion.

## Fix Requirement

Reject empty global unanchored `:S` patterns, or make zero-length matches advance before repeating.

## Patch Rationale

The patch rejects only the dangerous parser state before execution:

- The modifier must be `:S`, represented by `dosubst`.
- The parsed left-hand side must be empty, represented by `pattern->leftLen == 0`.
- The modifier must be exactly global and unanchored, represented by `VAR_SUB_GLOBAL` without `VAR_MATCH_START` or `VAR_MATCH_END`.

This prevents the non-advancing `strstr` loop while preserving non-`:S` modifiers, nonempty substitutions, nonglobal empty substitutions, and anchored empty substitutions.

## Residual Risk

None

## Patch

```diff
diff --git a/make/varmodifiers.c b/make/varmodifiers.c
index 2c2e352..2a5c5c5 100644
--- a/make/varmodifiers.c
+++ b/make/varmodifiers.c
@@ -1023,8 +1023,12 @@ common_get_patternarg(const char **p, SymTable *ctxt, bool err, int endc,
 				break;
 			}
 			if (*s == endc || *s == ':') {
-				*p = s;
-				return pattern;
+				if (!dosubst || pattern->leftLen != 0 ||
+				    (pattern->flags & (VAR_SUB_GLOBAL |
+				    VAR_MATCH_START | VAR_MATCH_END)) != VAR_SUB_GLOBAL) {
+					*p = s;
+					return pattern;
+				}
 			}
 		}
 	}
```