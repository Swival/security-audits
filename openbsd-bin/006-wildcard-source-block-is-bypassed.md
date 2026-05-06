# Wildcard Source Block Is Bypassed

## Classification

High severity policy bypass.

## Affected Locations

`smtpd/mta.c:406`

`smtpd/mta.c:418`

`smtpd/mta.c:1233`

`smtpd/mta.c:2552`

`smtpd/mta.c:2564`

`smtpd/mta.c:2568`

`smtpd/mta.c:2591`

`smtpd/mta.c:2612`

## Summary

An administrator wildcard MTA source block is stored as a `source/NULL` block entry, but normal outbound delivery checks only the exact `source/domain` key. Because `mta_is_blocked()` performs only one exact SPLAY lookup and does not fall back to `source/NULL`, wildcard source blocks do not apply to deliveries for nonempty destination domains.

## Provenance

Reproduced and patched from the verified finding. Scanner provenance: [Swival Security Scanner](https://swival.dev).

Confidence: certain.

## Preconditions

An administrator configures a source block with an empty domain wildcard.

## Proof

`IMSG_CTL_MTA_BLOCK` accepts a source and domain string. When the supplied domain is empty, it calls `mta_block(source, NULL)`, creating a wildcard block entry.

`mta_block()` stores that entry with:

```c
key.source = src;
key.domain = dom;
```

and persists `domain == NULL` for the wildcard case.

Normal delivery reaches `mta_connect()`, which checks:

```c
mta_is_blocked(c->source, c->relay->domain->name)
```

For remote delivery, `c->relay->domain->name` is a nonempty domain name.

Before the patch, `mta_is_blocked()` built only the exact key and performed one lookup:

```c
key.source = src;
key.domain = dom;

if (SPLAY_FIND(mta_block_tree, &blocks, &key))
	return (1);

return (0);
```

`mta_block_cmp()` treats `domain == NULL` and `domain != NULL` as distinct keys:

```c
if (!a->domain && b->domain)
	return (-1);
if (a->domain && !b->domain)
	return (1);
```

Therefore, a wildcard block stored as `source/NULL` cannot match a delivery lookup for `source/example.com`. The connector avoids `CONNECTOR_ERROR_BLOCKED`, and delivery proceeds over a source the administrator intended to pause.

## Why This Is A Real Bug

The code explicitly supports wildcard source blocks: empty administrative domain input is converted to `NULL`, and block display renders `NULL` as `*`. However, the enforcement path never checks the wildcard key when evaluating a concrete destination domain. This makes the administrative policy ineffective for the common remote-delivery path and allows any queued outbound delivery to a nonempty domain to bypass the wildcard block.

## Fix Requirement

`mta_is_blocked()` must check for an exact source/domain block first, then check for a wildcard source block represented by the same source and `domain == NULL`.

## Patch Rationale

The patch preserves exact domain block behavior and adds the missing wildcard fallback only when the caller supplied a concrete domain. This matches the existing data model where `NULL` is the wildcard domain sentinel and avoids changing block insertion, unblock semantics, SPLAY ordering, or display behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/smtpd/mta.c b/smtpd/mta.c
index 8022d23..de14cad 100644
--- a/smtpd/mta.c
+++ b/smtpd/mta.c
@@ -2598,6 +2598,10 @@ mta_is_blocked(struct mta_source *src, char *dom)
 	if (SPLAY_FIND(mta_block_tree, &blocks, &key))
 		return (1);
 
+	key.domain = NULL;
+	if (dom && SPLAY_FIND(mta_block_tree, &blocks, &key))
+		return (1);
+
 	return (0);
 }
```