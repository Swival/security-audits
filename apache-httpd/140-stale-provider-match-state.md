# Stale Provider Match State

## Classification

Logic error, medium severity.

## Affected Locations

`modules/filters/mod_filter.c:142`

## Summary

`filter_lookup()` keeps a single `match` variable across all provider iterations. When one provider matches its dispatch condition but is skipped by protocol checks, `match` remains set for the next provider. If the next provider does not match, the stale value can still select it, causing the wrong output filter provider to run.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A smart filter has multiple providers.
- An earlier provider matches its dispatch condition.
- That earlier provider is skipped by protocol checks, such as `proxy=no` on a proxy response.
- A later provider does not match its own dispatch condition.

## Proof

`filter_lookup()` initializes `match` once before the provider loop:

```c
int match = 0;
```

The loop then evaluates each provider. If an expression provider matches, `match` becomes `1`. If protocol handling rejects that provider, execution continues to the next provider without clearing `match`:

```c
if (proto_flags & AP_FILTER_PROTO_NO_PROXY) {
    /* can't use this provider; try next */
    continue;
}
```

For a following Content-Type provider, the code only sets `match = 1` when a type matches. It does not reset `match` before checking the provider. Therefore a nonmatching provider can inherit `match == 1`.

Reproduced trigger shape:

- A `BYTYPE` filter has provider A first with an expression that evaluates true.
- Provider A has `FilterProtocol ... proxy=no`.
- Provider B is intended only for `text/plain`.
- A proxy response has `Content-Type: text/html`.

Provider A matches but is skipped because proxy responses are disallowed. Provider B does not match `text/html`, but stale `match == 1` selects provider B anyway.

## Why This Is A Real Bug

Provider dispatch conditions are derived from request state, including expressions, `Content-Type`, proxy status, and `Cache-Control`. The loop is intended to decide each provider independently. Reusing a previous provider's successful match after a protocol `continue` violates that logic.

This can apply a configured transformation filter to responses outside its dispatch condition, causing unintended response modification or protocol header changes depending on the selected provider.

## Fix Requirement

Reset `match` to `0` at the start of every provider loop iteration so each provider is evaluated independently.

## Patch Rationale

The patch moves the effective initial state of `match` from once-per-lookup to once-per-provider. This preserves all existing match behavior for expression and Content-Type providers while preventing stale state from surviving across `continue` paths.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/filters/mod_filter.c b/modules/filters/mod_filter.c
index 5b5ecf6..a18dffb 100644
--- a/modules/filters/mod_filter.c
+++ b/modules/filters/mod_filter.c
@@ -148,6 +148,7 @@ static int filter_lookup(ap_filter_t *f, ap_filter_rec_t *filter)
 
     /* Check registered providers in order */
     for (provider = filter->providers; provider; provider = provider->next) {
+        match = 0;
         if (provider->expr) {
             match = ap_expr_exec(r, provider->expr, &err);
             if (err) {
```