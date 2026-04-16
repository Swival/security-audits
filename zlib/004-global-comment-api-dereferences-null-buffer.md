# Global comment API dereferences NULL buffer

## Classification
- Type: vulnerability
- Severity: medium
- Confidence: certain

## Affected Locations
- `contrib/minizip/unzip.c:1370`

## Summary
`unzGetGlobalComment` dereferences `szComment` before validating it when `uSizeBuf > 0` and the archive has a nonzero global comment. A caller can pass `NULL` as the destination buffer and trigger an immediate crash on crafted input that sets `s->gi.size_comment > 0`.

## Provenance
- Verified from source review and local reproduction against the committed codebase
- Reference: https://swival.dev

## Preconditions
- Call `unzGetGlobalComment` with `szComment == NULL`
- Pass `uSizeBuf > 0`
- Open a ZIP archive with a nonempty global comment
- Reach the non-Zip64 path where `s->gi.size_comment` is populated from EOCD metadata

## Proof
- `unzOpenInternal` parses EOCD metadata and stores the archive comment length in `s->gi.size_comment`
- `unzGetGlobalComment` computes `uReadThis` from `uSizeBuf`, caps it to `s->gi.size_comment`, seeks to `s->central_pos + 22`, and then executes `*szComment = '\0'` when `uReadThis > 0`
- The existing `(szComment != NULL)` check occurs later and does not protect that first write
- Local reproduction:
  - Created a ZIP with a 1-byte global comment
  - Built a small program that calls `unzOpen("tmp_global_comment.zip")` and then `unzGetGlobalComment(uf, NULL, 1)`
  - Execution crashes immediately with `Segmentation fault: 11`

## Why This Is A Real Bug
The crash occurs on a direct API call with attacker-influenced archive metadata and no undefined precondition documented by the function. The input archive controls whether `uReadThis` becomes nonzero, so a caller mistake or size-query style usage with `NULL` becomes reliably exploitable as denial of service. This is not theoretical; it is reproducible with a minimal archive and a single call.

## Fix Requirement
Guard `szComment` before any dereference or read/write operation. If `uReadThis > 0` and `szComment == NULL`, either reject the call with an error or treat it as a size-only query without touching memory.

## Patch Rationale
The patch adds an early `NULL` check before the initial terminator write and before any attempted read into the caller buffer. This preserves existing behavior for valid callers, prevents the crash path, and keeps the function's handling localized to the vulnerable API boundary.

## Residual Risk
None

## Patch
- Patch file: `004-global-comment-api-dereferences-null-buffer.patch`
- Patched location: `contrib/minizip/unzip.c`
- Change:
  ```diff
  -    if (uReadThis > 0)
  -        *szComment='\0';
  +    if ((uReadThis > 0) && (szComment == NULL))
  +        return UNZ_PARAMERROR;
  +    if (uReadThis > 0)
  +        *szComment='\0';
  ```
