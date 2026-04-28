# unchecked content length accumulation

## Classification

data integrity bug, medium severity, confidence: certain

## Affected Locations

`modules/http/byterange_filter.c:374`

## Summary

`ap_byterange_filter()` accumulates known bucket lengths into `apr_off_t clength` without checking for overflow. If the brigade’s total known length exceeds `APR_OFF_MAX`, `clength` can wrap or otherwise become incorrect, and later range parsing, satisfiability checks, copy decisions, and `Content-Range` generation use the corrupted entity length.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The response brigade reaches `ap_byterange_filter()`.
- The brigade contains EOS.
- All buckets before EOS have known lengths.
- The sum of those bucket lengths exceeds the maximum representable `apr_off_t`.

## Proof

Bucket lengths enter `ap_byterange_filter()` from the output brigade. The length scan adds each `e->length` into `apr_off_t clength` without validating whether the addition fits:

```c
clength += e->length;
```

Once `clength` is corrupted, it is passed to `ap_set_byterange()` and used for range satisfiability and normalization. It is also emitted in `Content-Range`.

Concrete reproduced path:

- A 64-bit APR-style build receives a brigade with EOS and known bucket lengths summing to `2^64 + 100`.
- The accumulated `clength` can become `100`.
- `Range: bytes=100-` is treated as unsatisfiable because `start >= clength`, producing `416` even though the real response has data at byte 100.
- `Range: bytes=0-99` can produce `206` with `Content-Range: bytes 0-99/100`, incorrectly reporting the total entity length.

The byterange filter is installed for main requests, so the path is reachable for ranged HTTP responses whose output brigade contains EOS and only known-length buckets.

## Why This Is A Real Bug

The filter’s correctness depends on `clength` being the actual entity length. When accumulation overflows, the filter makes protocol-visible decisions using a false length:

- valid ranges can be rejected as unsatisfiable;
- partial responses can advertise the wrong complete length;
- generated `Content-Range` values can be inconsistent with the real response body.

This is a data integrity failure in HTTP range handling, not merely an internal accounting issue.

## Fix Requirement

Before adding a bucket length to `clength`, verify that the length can be represented and that the addition will not exceed `APR_OFF_MAX`. On overflow risk, bypass range filtering and pass the original brigade downstream unchanged.

## Patch Rationale

The patch adds a guard inside the existing length scan:

```c
if (e->length > APR_OFF_MAX
    || clength > APR_OFF_MAX - (apr_off_t)e->length) {
    break;
}
clength += e->length;
```

Breaking out of the scan leaves `e` positioned on a non-EOS bucket. The existing post-scan condition then treats the brigade as unsuitable for byterange processing:

```c
if (!APR_BUCKET_IS_EOS(e) || clength <= 0) {
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}
```

This reuses the existing safe fallback path for incomplete, unknown, or unsuitable brigades and avoids generating range responses from an untrustworthy length.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/http/byterange_filter.c b/modules/http/byterange_filter.c
index a1ffdd3..6c605e1 100644
--- a/modules/http/byterange_filter.c
+++ b/modules/http/byterange_filter.c
@@ -436,6 +436,10 @@ AP_CORE_DECLARE_NONSTD(apr_status_t) ap_byterange_filter(ap_filter_t *f,
          (e != APR_BRIGADE_SENTINEL(bb) && !APR_BUCKET_IS_EOS(e)
           && e->length != (apr_size_t)-1);
          e = APR_BUCKET_NEXT(e)) {
+        if (e->length > APR_OFF_MAX
+            || clength > APR_OFF_MAX - (apr_off_t)e->length) {
+            break;
+        }
         clength += e->length;
     }
```