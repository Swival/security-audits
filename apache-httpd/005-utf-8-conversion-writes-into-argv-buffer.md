# UTF-8 conversion writes into argv buffer

## Classification

Memory safety, medium severity, certain confidence.

## Affected Locations

- `server/mpm/winnt/service.c:424`
- `server/mpm/winnt/service.c:430`

## Summary

In the Unicode Windows service entry point, extra arguments supplied through `StartServiceW()` are copied into the replacement argument vector as pointer values. The conversion loop then allocates a UTF-8 buffer for each argument but mistakenly passes the copied `argv` pointer as the conversion destination. This writes UTF-8 bytes into the original SCM-provided wide-character argument buffer instead of the allocated buffer.

The patch changes the conversion destination to the allocated `service_name` buffer and stores that owned UTF-8 pointer in the replacement argument vector.

## Provenance

Found by Swival Security Scanner: https://swival.dev

## Preconditions

- Windows Unicode build with `APR_HAS_UNICODE_FS`.
- Service entry point receives `argc > 1` from `StartServiceW()`.
- The SCM starts the service with one or more extra arguments.

## Proof

`service_nt_main_fn_w(DWORD argc, LPWSTR *argv)` receives SCM service arguments as wide strings.

When `argc > 1`, the code builds a replacement argument vector:

```c
memcpy (cmb_data + mpm_new_argv->nelts, argv + 1,
        mpm_new_argv->elt_size * (argc - 1));

cmb = cmb_data + mpm_new_argv->nelts;
```

At this point, `cmb` points at slots containing copied `LPWSTR` argument pointers from `argv + 1`.

The loop allocates a UTF-8 destination buffer:

```c
service_name = malloc(slen);
```

But the vulnerable code passes `*(cmb++)` as the destination:

```c
(void)apr_conv_ucs2_to_utf8(argv[i], &wslen, *(cmb++), &slen);
```

Therefore the conversion writes UTF-8 bytes into the original wide `argv[i]` storage rather than into `service_name`. The allocated buffer is unused, and `mpm_new_argv->elts` later stores pointers to the overwritten SCM wide buffers.

This path is reachable from service start: the Unicode branch of `mpm_service_start()` calls `StartServiceW()`, and the service callback enters this block whenever extra service arguments are supplied.

## Why This Is A Real Bug

The destination pointer type and allocation intent show that each wide service argument should be converted into a newly allocated UTF-8 `char *`. Instead, the code writes the UTF-8 output into memory owned by the SCM argument array.

This corrupts the wide argument buffer for ordinary ASCII input. For non-ASCII BMP input, UTF-8 output can require more bytes than the corresponding UTF-16 buffer. For example, two U+0800 characters require 7 UTF-8 bytes including NUL, while the exact UTF-16 representation requires 6 bytes including NUL. Because the code passes the larger UTF-8 capacity while using the original wide buffer as the destination, this can become an out-of-bounds write.

## Fix Requirement

The conversion must write into the newly allocated UTF-8 buffer, and the replacement argument vector must store that buffer pointer.

## Patch Rationale

The patch preserves the existing allocation and conversion sizing logic, but corrects the destination and ownership:

- `apr_conv_ucs2_to_utf8()` writes to `service_name`.
- The current replacement argument slot is updated to `service_name`.
- `cmb` is incremented only after storing the converted pointer.

This ensures `mpm_new_argv->elts` contains owned UTF-8 strings rather than pointers to corrupted SCM wide buffers.

## Residual Risk

None

## Patch

```diff
diff --git a/server/mpm/winnt/service.c b/server/mpm/winnt/service.c
index 2e473cf..5e9f34c 100644
--- a/server/mpm/winnt/service.c
+++ b/server/mpm/winnt/service.c
@@ -430,7 +430,8 @@ static void __stdcall service_nt_main_fn_w(DWORD argc, LPWSTR *argv)
             wslen = wcslen(argv[i]) + 1;
             slen = wslen * 3 - 2;
             service_name = malloc(slen);
-            (void)apr_conv_ucs2_to_utf8(argv[i], &wslen, *(cmb++), &slen);
+            (void)apr_conv_ucs2_to_utf8(argv[i], &wslen, service_name, &slen);
+            *(cmb++) = service_name;
         }
 
         /* The replacement arg list is complete */
```