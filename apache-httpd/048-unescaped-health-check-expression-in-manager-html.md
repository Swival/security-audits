# Unescaped Health Check Expression In Manager HTML

## Classification

Medium severity stored HTML injection / stored cross-site scripting risk.

Confidence: certain.

## Affected Locations

`modules/proxy/mod_proxy_balancer.c:1231`

`modules/proxy/mod_proxy_balancer.c:1751`

## Summary

`balancer-manager` stores a worker health check expression name in `worker->s->hcexpr` and later renders it into the HTML manager table without HTML escaping. A valid health check expression name containing HTML metacharacters is emitted as markup when the manager page displays health check columns.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

The finding was reproduced from the supplied source and patched in `048-unescaped-health-check-expression-in-manager-html.patch`.

## Preconditions

An attacker can store a health check expression containing HTML metacharacters.

Practical paths include:

- A configured health check expression name such as `ProxyHCExpr <svg/onload=1> {...valid ap_expr...}`.
- A balancer-manager POST parameter `w_he=%3Csvg%2Fonload%3D1%3E` with valid balancer selection, nonce, same-host referer, and a health-check method supporting expressions.
- Health check columns are enabled in the manager table through `set_worker_hc_param_f`.

## Proof

`balancer_handler` accepts POST data and passes parameters to `balancer_process_balancer_worker`.

`balancer_process_balancer_worker` reads `w_he`, checks only that it is non-empty, accepted by `hc_valid_expr_f`, and fits in `wsel->s->hcexpr`, then copies it into persistent worker state:

```c
if (hc_valid_expr_f && (val = apr_table_get(params, "w_he"))) {
    if (strlen(val) && hc_valid_expr_f(r, val) && strlen(val) < sizeof(wsel->s->hcexpr))
        strcpy(wsel->s->hcexpr, val);
    else
        *wsel->s->hcexpr = '\0';
}
```

`balancer_display_page` later emits that stored value into an HTML table cell without escaping:

```c
ap_rprintf(r, "<td>%s", worker->s->hcexpr);
```

A stored value such as `<svg/onload=1>` is therefore interpreted by the browser as HTML rather than displayed as text.

## Why This Is A Real Bug

Other adjacent string fields in the same manager page are escaped before HTML output, including `worker->s->hcuri`, `worker->s->route`, and `worker->s->redirect`. `worker->s->hcexpr` is attacker-influenced under the stated preconditions and is rendered in the same HTML context without `ap_escape_html`.

`hc_valid_expr_f` validates that the named expression exists; it does not make the expression name safe for HTML output. The reproduced trigger confirms that valid configured expression names can contain HTML metacharacters and reach the vulnerable sink.

## Fix Requirement

Escape `worker->s->hcexpr` with `ap_escape_html(r->pool, ...)` before writing it into the HTML response.

## Patch Rationale

The patch applies output encoding at the HTML sink, matching the established pattern used for nearby health check URI and worker route fields. This preserves stored values and validation behavior while preventing the browser from interpreting metacharacters as markup.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/proxy/mod_proxy_balancer.c b/modules/proxy/mod_proxy_balancer.c
index f5b228f..49e2d99 100644
--- a/modules/proxy/mod_proxy_balancer.c
+++ b/modules/proxy/mod_proxy_balancer.c
@@ -1748,7 +1748,7 @@ static void balancer_display_page(request_rec *r, proxy_server_conf *conf,
                     ap_rprintf(r, "<td>%d (%d)</td>", worker->s->passes,worker->s->pcount);
                     ap_rprintf(r, "<td>%d (%d)</td>", worker->s->fails, worker->s->fcount);
                     ap_rprintf(r, "<td>%s</td>", ap_escape_html(r->pool, worker->s->hcuri));
-                    ap_rprintf(r, "<td>%s", worker->s->hcexpr);
+                    ap_rprintf(r, "<td>%s", ap_escape_html(r->pool, worker->s->hcexpr));
                 }
                 ap_rputs("</td></tr>\n", r);
```