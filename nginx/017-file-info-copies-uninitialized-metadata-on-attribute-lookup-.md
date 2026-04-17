# File info copies uninitialized metadata on attribute lookup failure

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/os/win32/ngx_files.c:350`
- `src/os/win32/ngx_files.c:416`
- `src/os/win32/ngx_files.c:423`

## Summary
On Windows, `ngx_file_info()` calls `GetFileAttributesExW()` and stores the result in a stack `WIN32_FILE_ATTRIBUTE_DATA fa`. When the API call fails, the function still copied `fa` into `*sb` before returning `NGX_FILE_ERROR`. Because `fa` is then indeterminate, the caller-visible `ngx_file_info_t` output buffer receives uninitialized metadata on the error path.

## Provenance
- Verified from source and reproducer notes supplied for this finding
- Scanner provenance: https://swival.dev

## Preconditions
- `GetFileAttributesExW()` returns `0` inside `ngx_file_info()`

## Proof
In `ngx_file_info()`, `fa` is a local stack object populated only by `GetFileAttributesExW()`. The code assigns:
```c
rc = ngx_win32_check_filename(u, len);

if (rc != NGX_OK) {
    goto failed;
}

if (GetFileAttributesExW(u, GetFileExInfoStandard, &fa) == 0) {
    rc = NGX_FILE_ERROR;
}

*sb = fa;

failed:

ngx_free(u);

return rc;
```

If `GetFileAttributesExW()` returns `0`, `rc` becomes `NGX_FILE_ERROR`, but execution still reaches `*sb = fa;`. Since the Windows API did not initialize `fa` on failure, that assignment copies indeterminate stack data into the caller-provided output structure before the function returns the error.

The patch gates the copy on success so `*sb` is written only when the attribute query succeeds.

## Why This Is A Real Bug
The function contract exposes `sb` as an output parameter. Writing indeterminate stack contents into it is incorrect regardless of the returned error code, because it creates observable undefined state for any caller that inspects or later propagates the structure. The reproduced notes also show the broader Windows file-info path already suffers from uninitialized metadata usage in downstream control decisions, making this failure-path write a concrete bug rather than a theoretical coding-style issue.

## Fix Requirement
Only copy `fa` into `*sb` when `GetFileAttributesExW()` succeeds. On failure, return `NGX_FILE_ERROR` without writing uninitialized metadata to the output buffer.

## Patch Rationale
The patch is minimal and directly aligned with the failing condition: it moves or guards the `*sb = fa;` assignment so it executes only after a successful `GetFileAttributesExW()` call. This preserves existing success behavior and eliminates the erroneous propagation of uninitialized stack data on the error path.

## Residual Risk
None

## Patch
- Patched file: `src/os/win32/ngx_files.c`
- Patch artifact: `017-file-info-copies-uninitialized-metadata-on-attribute-lookup-.patch`