# publishConfig tag injects dist-tags

## Classification

Injection, medium severity. Confidence: certain.

## Affected Locations

`src/runtime/cli/publish_command.rs:2090`

## Summary

A tarball-controlled `publishConfig.tag` value was copied into publish options and later interpolated directly as a JSON object key in the authenticated npm publish request body. Because the tag key was not JSON-escaped, a malicious package tarball could inject additional `dist-tags` into the registry payload published under the victim publisher's credentials.

## Provenance

Verified finding from Swival.dev Security Scanner: https://swival.dev

## Preconditions

Victim publishes an attacker-supplied tarball with valid registry credentials.

## Proof

`from_tarball_path` parses the tarball `package.json` and copies `publishConfig.tag` into `manager.options.publish_config.tag` when no CLI tag is set.

`construct_publish_request_body` then selects that tag and previously emitted it into the JSON body using raw `bstr` formatting:

```rust
,"dist-tags":{"{}":"{}"}
```

A malicious tarball can contain a valid JSON string:

```json
{
  "name": "pkg",
  "version": "1.2.3",
  "publishConfig": {
    "tag": "latest\":\"1.2.3\",\"beta"
  }
}
```

Before the patch, this produced the following `dist-tags` fragment:

```json
"dist-tags":{"latest":"1.2.3","beta":"1.2.3"}
```

The injected `beta` dist-tag is attacker-controlled registry metadata submitted in the victim's authenticated publish `PUT` request.

## Why This Is A Real Bug

The tag value originates from attacker-controlled tarball metadata and is trusted when publishing a tarball. The publish request body is constructed by manual string formatting, not by a JSON serializer, so quotes and object syntax in the tag escape the intended key context. The resulting JSON is syntactically valid and changes the semantic content of the authenticated registry request by adding attacker-chosen dist-tags.

## Fix Requirement

The `dist-tags` key must be serialized as a JSON string, or otherwise JSON-escaped, before insertion into the publish request body. Manual interpolation of untrusted bytes into JSON syntax must not be used for object keys.

## Patch Rationale

The patch replaces raw quoted interpolation of `tag` with `bun_js_printer::write_json_string`, which emits a valid JSON string literal for the tag key. This preserves legitimate tag values while escaping embedded quotes and control characters so attacker input remains data, not JSON structure.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/cli/publish_command.rs b/src/runtime/cli/publish_command.rs
index a18a294d52..d0add479e5 100644
--- a/src/runtime/cli/publish_command.rs
+++ b/src/runtime/cli/publish_command.rs
@@ -2085,10 +2085,12 @@ impl PublishCommand {
         )
         .ok();
 
+        write!(&mut buf, ",\"dist-tags\":{{").ok();
+        bun_js_printer::write_json_string::<_, { bun_js_printer::Encoding::Utf8 }>(tag, &mut buf)
+            .map_err(|_| AllocError)?;
         write!(
             &mut buf,
-            ",\"dist-tags\":{{\"{}\":\"{}\"}}",
-            bstr::BStr::new(tag),
+            ":\"{}\"}}",
             bstr::BStr::new(version_without_build_tag),
         )
         .ok();
```