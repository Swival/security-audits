# Slot Allocation Size Overflow

## Classification

Memory safety, medium severity. Confidence: certain.

## Affected Locations

`modules/slotmem/mod_slotmem_plain.c:72`

## Summary

`slotmem_create()` multiplied attacker- or caller-controlled `item_size` and `item_num` without checking for `apr_size_t` overflow. When the multiplication wrapped, the module allocated a buffer smaller than the logical slot area, while later slot access still used the original oversized `item_size` and `item_num`. This allowed out-of-bounds reads and writes through the plain slotmem provider.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A caller can request large `item_size` and `item_num` values through the registered plain slotmem provider `create` callback.

## Proof

`slotmem_create()` computed:

```c
apr_size_t basesize = (item_size * item_num);
```

without overflow checking.

With `item_size = 1 << 48` and `item_num = 65536`, the logical slot area is `2^64` bytes, but the multiplication wraps to `0`. The resulting allocation is only the in-use table size:

```c
res->base = apr_pcalloc(gpool, basesize + (item_num * sizeof(char)));
```

The reproduced harness printed:

```text
wrapped_basesize=0 allocation=65536
```

This also corrupts the internal layout because:

```c
res->inuse = (char *)res->base + basesize;
```

places `res->inuse` at the start of the allocation after `basesize` wraps.

Subsequent slot lookup still trusts the original slot size:

```c
ptr = (char *)score->base + score->size * id;
```

For `id = 1`, this computes a pointer at `base + 0x1000000000000` while passing the `id < num` validation. `slotmem_put()` then reaches:

```c
memcpy(ptr, src, src_len);
```

and the reproduced harness crashed with `Segmentation fault` when writing one byte. `slotmem_get()` similarly permits an out-of-bounds read.

## Why This Is A Real Bug

The allocation size and the addressing arithmetic are derived from the same unchecked product, but only the allocation observes the wrapped value. The instance records the unwrapped logical dimensions in `res->size` and `res->num`, so later bounds checks validate only `id < num` and do not prove that `base + size * id` falls within the allocated object. This creates a concrete mismatch between allocated memory and accessible slot addresses.

## Fix Requirement

Reject requests where `item_size * item_num` cannot be represented in `apr_size_t` before calculating `basesize`.

## Patch Rationale

The patch delays `basesize` initialization and adds an overflow guard:

```c
if (item_num && item_size > APR_SIZE_MAX / item_num) {
    return APR_EINVAL;
}
basesize = item_size * item_num;
```

This ensures `basesize` accurately represents the requested slot area whenever allocation proceeds. The `item_num` check avoids division by zero, and `APR_EINVAL` correctly rejects invalid sizing parameters before any allocation or instance state is created.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/slotmem/mod_slotmem_plain.c b/modules/slotmem/mod_slotmem_plain.c
index 4c2b19b..3563d91 100644
--- a/modules/slotmem/mod_slotmem_plain.c
+++ b/modules/slotmem/mod_slotmem_plain.c
@@ -67,10 +67,15 @@ static apr_status_t slotmem_create(ap_slotmem_instance_t **new, const char *name
 {
     ap_slotmem_instance_t *res;
     ap_slotmem_instance_t *next = globallistmem;
-    apr_size_t basesize = (item_size * item_num);
+    apr_size_t basesize;
 
     const char *fname;
 
+    if (item_num && item_size > APR_SIZE_MAX / item_num) {
+        return APR_EINVAL;
+    }
+    basesize = item_size * item_num;
+
     if (name) {
         if (name[0] == ':')
             fname = name;
```