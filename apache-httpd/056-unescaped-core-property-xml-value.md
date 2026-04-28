# Unescaped Core Property XML Value

## Classification

Medium severity vulnerability.

## Affected Locations

`modules/dav/main/props.c:435`

## Summary

`dav_insert_coreprop()` inserted `DAV:getcontenttype` and `DAV:getcontentlanguage` text directly into PROPFIND XML responses. Those values are sourced from subrequest metadata and were concatenated between XML tags without escaping, so XML metacharacters could produce malformed XML or XML element injection in DAV responses.

## Provenance

Found by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A PROPFIND response includes core DAV property values.
- Subrequest content metadata contains XML metacharacters, such as `<`, `>`, or `&`.
- The affected value is emitted through `DAV_PROP_INSERT_VALUE`.

## Proof

`DAV:getcontenttype` is populated from a GET subrequest:

- `modules/dav/main/props.c:397` performs the subrequest.
- `modules/dav/main/props.c:401` reads `propdb->subreq->content_type`.

`DAV:getcontentlanguage` is populated from subrequest headers:

- `modules/dav/main/props.c:405` reads `Content-Language`.

The vulnerable sink is the value insertion path:

- `modules/dav/main/props.c:437` concatenates `value` directly into `<D:name>value</D:name>` with `apr_pstrcat()`.
- `dav_send_one_response()` later writes `propstats` raw and assumes it is already quoted at `modules/dav/main/mod_dav.c:522`.

A reproduced malformed response example is:

```xml
<D:getcontenttype>text/x<foo</D:getcontenttype>
```

This is reachable from `dav_get_allprops()` and `dav_get_props()` PROPFIND responses.

The `lockdiscovery` portion of the original report is not proven for the standard path: `lockdiscovery` intentionally embeds XML fragments, and the standard owner path quotes owner XML before storage in `modules/dav/main/util_lock.c:226`.

## Why This Is A Real Bug

XML text nodes must escape metacharacters before insertion. The affected code inserted externally derived metadata directly into response XML, while the output path treated the accumulated `propstats` as already safe. This allows a metadata value containing XML syntax to corrupt the DAV multistatus response and can cause DAV clients or XML parsers to fail. For metadata providers that preserve attacker-controlled XML syntax, the same sink can inject XML elements into the response.

## Fix Requirement

XML-escape core property text before inserting it between XML tags.

The escaping must apply to text-valued core properties sourced from subrequest metadata:

- `DAV:getcontenttype`
- `DAV:getcontentlanguage`

It must not escape `DAV:lockdiscovery` or `DAV:supportedlock`, because those properties intentionally return XML fragments rather than plain text.

## Patch Rationale

The patch introduces `xml_value` for the `DAV_PROP_INSERT_VALUE` path and applies `apr_xml_quote_string()` only for `DAV_PROPID_CORE_getcontenttype` and `DAV_PROPID_CORE_getcontentlanguage`.

This preserves existing XML-fragment behavior for `lockdiscovery` and `supportedlock`, while ensuring plain text metadata is safely serialized as XML text.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/dav/main/props.c b/modules/dav/main/props.c
index c320f8a..ad44bda 100644
--- a/modules/dav/main/props.c
+++ b/modules/dav/main/props.c
@@ -435,8 +435,15 @@ static dav_error * dav_insert_coreprop(dav_propdb *propdb,
                             name, "\"/>" DEBUG_CR, NULL);
         }
         else if (what == DAV_PROP_INSERT_VALUE && *value != '\0') {
+            const char *xml_value = value;
+
+            if (propid == DAV_PROPID_CORE_getcontenttype
+                || propid == DAV_PROPID_CORE_getcontentlanguage) {
+                xml_value = apr_xml_quote_string(propdb->p, value, 0);
+            }
+
             /* use D: prefix to refer to the DAV: namespace URI */
-            s = apr_pstrcat(propdb->p, "<D:", name, ">", value, "</D:", name,
+            s = apr_pstrcat(propdb->p, "<D:", name, ">", xml_value, "</D:", name,
                             ">" DEBUG_CR, NULL);
         }
         else {
```