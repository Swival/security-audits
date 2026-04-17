# Untrusted XML Enables External Entity Expansion

## Classification
- Type: trust-boundary violation
- Severity: high
- Confidence: certain

## Affected Locations
- `src/http/modules/ngx_http_xslt_filter_module.c:289`

## Summary
- The XSLT filter parses attacker-controlled XML response data with libxml2 options `XML_PARSE_NOENT|XML_PARSE_DTDLOAD`.
- This enables entity substitution during parse and permits external entity resolution from untrusted XML before stylesheet processing.
- An attacker who controls a matching XML response body can trigger XXE, including local file disclosure.

## Provenance
- Report reproduced and patched from a verified finding.
- Reference: Swival Security Scanner at https://swival.dev

## Preconditions
- The XSLT filter processes an attacker-controlled XML response body.

## Proof
- Untrusted body chunks reach `ngx_http_xslt_add_chunk()`, which creates a push parser and applies `xmlCtxtUseOptions(ctxt, XML_PARSE_NOENT|XML_PARSE_DTDLOAD)` at `src/http/modules/ngx_http_xslt_filter_module.c:289`.
- `xmlParseChunk()` then parses attacker-controlled XML with entity expansion enabled.
- Reproduction confirmed that the existing `externalSubset` hook only clears `ctxt->myDoc->extSubset` and `ctxt->myDoc->intSubset->children->next` at `src/http/modules/ngx_http_xslt_filter_module.c:413` and `src/http/modules/ngx_http_xslt_filter_module.c:459`, which does not prevent external general entities declared in the internal subset.
- A minimal libxml2 PoC using the same parser setup expanded `<!ENTITY ext SYSTEM 'file:///etc/passwd'>` from attacker-controlled XML and exposed file contents in parsed element text.

## Why This Is A Real Bug
- The vulnerable behavior occurs during parsing of untrusted response data, before any trusted transformation logic can constrain it.
- `XML_PARSE_NOENT` instructs libxml2 to substitute entities into document content, making XXE directly reachable from attacker input.
- `XML_PARSE_DTDLOAD` further broadens external resource exposure by allowing DTD loading during parse.
- The existing callback-based mitigation is incomplete and does not stop the demonstrated internal-subset XXE path.

## Fix Requirement
- Stop parsing request XML with `XML_PARSE_NOENT` and `XML_PARSE_DTDLOAD`.
- Preserve normal XML parsing without enabling external entity expansion or external DTD loading for untrusted input.

## Patch Rationale
- The patch removes the unsafe libxml2 parse options from the untrusted XML parsing path in `src/http/modules/ngx_http_xslt_filter_module.c`.
- This directly blocks the reproduced XXE primitive instead of relying on partial post-hoc sanitization of DTD structures.
- The change is minimal and aligned with the intended fix outline for this finding.

## Residual Risk
- None

## Patch
- Patch file: `009-untrusted-xml-enables-external-entity-expansion.patch`