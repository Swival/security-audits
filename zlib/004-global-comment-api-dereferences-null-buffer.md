# Global comment API NULL buffer dereference

## Classification
- Type: vulnerability
- Severity: medium
- Confidence: certain

## Affected Locations
- `contrib/minizip/unzip.c:1370`

## Summary
`unzGetGlobalComment` dereferences `szComment` before validating it when `uSizeBuf > 0` and the archive global comment is nonempty. A caller passing `NULL` for size-query or by mistake can be crashed by a crafted ZIP, causing denial of service.

## Provenance
- Verified by local reproduction and patching against the reported code path
- External scanner reference: https://swival.dev

## Preconditions
- Call `unzGetGlobalComment` with `szComment == NULL`
- Pass `uSizeBuf > 0`
- Open a ZIP archive with a nonempty global comment
- Reach the non-Zip64 path where `s->gi.size_comment` is populated from EOCD metadata

## Proof
- `unzOpenInternal` stores the EOCD comment length in `s->gi.size_comment`
- `unzGetGlobalComment` computes `uReadThis` from `uSizeBuf`, caps it to `s->gi.size_comment`, and seeks to `s->central_pos + 22`
- When `uReadThis > 0`, the function executes `*szComment = '\0'` before any NULL check
- The later `(szComment != NULL)` guard is therefore ineffective for the first dereference
- Reproducer:
  - Created a ZIP with a 1-byte global comment
  - Opened it with `unzOpen("tmp_global_comment.zip")`
  - Called `unzGetGlobalComment(uf, NULL, 1)`
  - Process crashed immediately with `Segmentation fault: 11`

## Why This Is A Real Bug
The crash is directly reachable through a public API with attacker-controlled archive metadata. The dereference occurs before any protective branch, so a nonempty global comment reliably converts a `NULL` buffer into an immediate process crash. This is a real denial-of-service condition even though it does not provide memory corruption primitives.

## Fix Requirement
Validate `szComment` before any dereference or read attempt. If `uReadThis > 0` and `szComment == NULL`, either reject the call with an error or treat it as a size-only query without touching memory.

## Patch Rationale
The patch adds an early `NULL` check in `unzGetGlobalComment` before `*szComment = '\0'` and before any read into the caller buffer. This preserves existing behavior for valid callers while preventing the crash path for invalid `NULL` buffers with positive lengths.

## Residual Risk
None

## Patch
Patched in `004-global-comment-api-dereferences-null-buffer.patch`.