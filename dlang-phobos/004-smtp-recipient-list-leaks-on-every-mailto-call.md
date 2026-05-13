# SMTP recipient list leaks on every mailTo call

## Classification
- Type: resource lifecycle bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/net/curl.d:2408`

## Summary
`SMTP.mailTo` allocates a new `curl_slist` for `CURLOPT_MAIL_RCPT` on each call but does not retain ownership of that list in `SMTP.Impl`. Because libcurl does not copy this option and the existing `SMTP` destructor only cleans up the CURL handle, each repeated `mailTo` call on a reused `SMTP` instance leaks the previously configured recipient list.

## Provenance
- Reproduced from the verified finding and validated against the implementation in `std/net/curl.d`
- Scanner source: https://swival.dev

## Preconditions
- A single `SMTP` instance is reused
- `mailTo` is called more than once on that instance

## Proof
- `SMTP.mailTo` constructs a fresh `curl_slist* recipients_list` from caller-supplied recipients and passes it to `CurlOption.mail_rcpt`.
- libcurl documents `CURLOPT_MAIL_RCPT` as non-copying: the caller must keep the list alive until transfer completion and must free it with `curl_slist_free_all`.
- `SMTP.Impl` does not store the active recipient-list pointer.
- `SMTP.Impl` destructor frees only the CURL handle, unlike nearby wrappers that track and release owned slists.
- Repeating `mailTo` overwrites libcurl's configured pointer with a new list, making the previous list unreachable from D code and therefore leaked.

## Why This Is A Real Bug
This is a concrete ownership mismatch, not a theoretical concern. The wrapper allocates a native linked list whose lifetime must be managed explicitly, but it never records or frees that allocation. Reusing `SMTP` for multiple messages is a normal usage pattern, so long-lived processes will accumulate leaked native memory proportional to recipient count and number of `mailTo` calls.

## Fix Requirement
`SMTP.Impl` must own the active recipient `curl_slist`, free any existing list before installing a replacement, and release the final list during destruction.

## Patch Rationale
The patch adds recipient-list ownership to `SMTP.Impl`, mirroring existing slist management patterns used by other curl wrappers in the same module. Freeing the previous list before assigning a new one prevents per-call leaks, and freeing the tracked list in the destructor closes the remaining lifetime gap at object teardown without changing external API behavior.

## Residual Risk
None

## Patch
- Patch file: `004-smtp-recipient-list-leaks-on-every-mailto-call.patch`
- Expected change in `std/net/curl.d`:
```diff
 struct Impl
 {
     CURL* curl;
+    curl_slist* recipients;
 
     ~this()
     {
+        if (recipients !is null)
+            curl_slist_free_all(recipients);
         if (curl !is null)
             curl_easy_cleanup(curl);
     }
 }
```

```diff
-    curl_slist* recipients_list = null;
+    curl_slist* recipients_list = null;
     foreach (recipient; recipients)
         recipients_list = curl_slist_append(recipients_list, toStringz(recipient));
+    if (pimpl.recipients !is null)
+        curl_slist_free_all(pimpl.recipients);
+    pimpl.recipients = recipients_list;
-    set(CurlOption.mail_rcpt, recipients_list);
+    set(CurlOption.mail_rcpt, pimpl.recipients);
```