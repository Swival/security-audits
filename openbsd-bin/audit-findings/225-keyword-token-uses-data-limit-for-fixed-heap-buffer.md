# keyword token uses data limit for fixed heap buffer

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`sbin/unwind/libunbound/sldns/parse.c:508`

## Summary

`sldns_bget_keyword_data()` allocates a fixed `LDNS_MAX_KEYWORDLEN` heap buffer for `fkeyword`, but reads the attacker-controlled keyword token into it using the caller-controlled `data_limit`. If `data_limit` exceeds `LDNS_MAX_KEYWORDLEN`, an overlong token can write past the heap allocation before a delimiter is reached.

## Provenance

Found by Swival Security Scanner: https://swival.dev

## Preconditions

- Caller invokes `sldns_bget_keyword_data()` with an attacker-controlled `sldns_buffer`.
- Caller supplies `data_limit > LDNS_MAX_KEYWORDLEN`.
- The buffer contains a keyword token longer than `LDNS_MAX_KEYWORDLEN` before `k_del`.

## Proof

- `sldns_bget_keyword_data()` allocates `fkeyword` with `malloc(LDNS_MAX_KEYWORDLEN)`.
- It only checks `strlen(keyword) >= LDNS_MAX_KEYWORDLEN`, which constrains the expected keyword string, not the parsed token.
- It then calls `sldns_bget_token(b, fkeyword, k_del, data_limit)`.
- `sldns_bget_token_par()` enforces writes only against the supplied `limit`.
- `sldns_bget_token_par()` writes each non-delimiter byte with `*t++ = c`.
- A reproduced ASan harness using a 50-byte keyword token and `data_limit = sizeof(data)` produced a `heap-buffer-overflow` writing past the 32-byte allocation.

## Why This Is A Real Bug

The destination buffer size and the token parser limit are inconsistent. The heap allocation is fixed at `LDNS_MAX_KEYWORDLEN`, but the parser is allowed to write up to `data_limit`. Because `data_limit` is caller-controlled and may be larger than the allocation, parser bounds checks do not protect `fkeyword`.

The existing `strlen(keyword)` guard does not mitigate this because it validates the trusted comparison string, not the attacker-controlled token being copied from `sldns_buffer`.

## Fix Requirement

Pass `LDNS_MAX_KEYWORDLEN` as the token-read limit when reading into `fkeyword`.

## Patch Rationale

The patch makes the parser limit match the actual allocation size of `fkeyword`. This preserves the existing fixed-size keyword buffer design and causes overlong keyword tokens to fail through `sldns_bget_token()` instead of overflowing the heap buffer.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/unwind/libunbound/sldns/parse.c b/sbin/unwind/libunbound/sldns/parse.c
index 8ea0846..7f049a9 100644
--- a/sbin/unwind/libunbound/sldns/parse.c
+++ b/sbin/unwind/libunbound/sldns/parse.c
@@ -502,7 +502,7 @@ sldns_bget_keyword_data(sldns_buffer *b, const char *keyword, const char *k_del,
        if(!fkeyword)
                return -1; /* out of memory */
 
-       i = sldns_bget_token(b, fkeyword, k_del, data_limit);
+       i = sldns_bget_token(b, fkeyword, k_del, LDNS_MAX_KEYWORDLEN);
        if(i==0 || i==-1) {
                free(fkeyword);
                return -1; /* nothing read */
```