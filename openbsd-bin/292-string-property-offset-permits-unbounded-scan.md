# String Property Offset Permits Unbounded Scan

## Classification

denial of service, medium severity

## Affected Locations

- `usr.sbin/ldomctl/mdesc.c:473`
- `usr.sbin/ldomctl/mdesc.c:474`
- `usr.sbin/ldomctl/mdesc.c:206`
- `usr.sbin/ldomctl/mdstore.c:484`
- `usr.sbin/ldomctl/mdstore.c:486`

## Summary

`md_ingest()` trusted `MD_PROP_STR` `data_offset` values from an input MD file. It formed a pointer into `data_blk` without checking that the offset was inside the data block or that the referenced string contained a NUL terminator before the end of the block. The pointer then reached `md_add_prop_str()`, where `strlen()` performed an unbounded read. A crafted MD file can therefore crash `ldomctl` during parsing.

## Provenance

- Confidence: certain
- Source: reproduced and patched finding
- Scanner: Swival Security Scanner, https://swival.dev

## Preconditions

- `ldomctl` reads an attacker-controlled MD file.
- A lower-privileged local user can provide or influence the MD file consumed by a command such as `ldomctl download <dir>` via `<dir>/hv.md`.

## Proof

The vulnerable path is direct:

1. `md_ingest()` parses attacker-controlled block sizes from the MD header.
2. For `MD_PROP_STR`, it computed:
   ```c
   data = data_blk + betoh32(mde->d.y.data_offset);
   ```
3. It passed that unchecked pointer to:
   ```c
   md_add_prop_str(md, node, str, data);
   ```
4. `md_add_prop_str()` called:
   ```c
   strlen(str) + 1
   ```
5. A crafted string property with `data_offset` pointing to the final non-NUL byte of `data_blk`, or outside the valid data block, caused `strlen()` to read past the mapped allocation.

A small ASan harness using the committed `mdesc.c` and a crafted `MD_PROP_STR` aborted in `strlen()` called from `md_add_prop_str()`.

## Why This Is A Real Bug

The MD file is parsed as untrusted input, but the string property offset was used as a raw pointer displacement without bounds validation. `strlen()` requires a valid NUL-terminated string. The parser did not establish that condition, so malformed input controlled both the starting address and the absence of an in-block terminator. The resulting out-of-bounds read is sufficient to crash the process, producing a practical local denial of service against commands that ingest MD files.

## Fix Requirement

For `MD_PROP_STR`, validate before calling `md_add_prop_str()`:

- `data_offset` must be less than `data_blk_size`.
- A NUL byte must exist within `data_blk` at or after `data_offset`.
- Invalid input must be rejected as corrupt MD data.

## Patch Rationale

The patch stores the decoded `data_offset` in a local `uint32_t offset`, checks that it is inside `data_blk`, and uses `memchr()` to require a NUL terminator within the remaining bytes of the data block. Only after both checks pass does it form `data_blk + offset` and pass the pointer to `md_add_prop_str()`.

This prevents `strlen()` from scanning outside `data_blk` for string properties.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ldomctl/mdesc.c b/usr.sbin/ldomctl/mdesc.c
index 3cae1f7..50b90a5 100644
--- a/usr.sbin/ldomctl/mdesc.c
+++ b/usr.sbin/ldomctl/mdesc.c
@@ -430,6 +430,7 @@ md_ingest(void *buf, size_t size)
 	uint8_t *node_blk;
 	uint8_t *name_blk;
 	uint8_t *data_blk;
+	uint32_t offset;
 	uint64_t index;
 
 	if (size < sizeof(struct md_header))
@@ -470,7 +471,11 @@ md_ingest(void *buf, size_t size)
 			if (node == NULL)
 				errx(1, "Corrupt MD");
 			str = name_blk + betoh32(mde->name_offset);
-			data = data_blk + betoh32(mde->d.y.data_offset);
+			offset = betoh32(mde->d.y.data_offset);
+			if (offset >= data_blk_size ||
+			    memchr(data_blk + offset, '\0', data_blk_size - offset) == NULL)
+				errx(1, "Corrupt MD");
+			data = data_blk + offset;
 			md_add_prop_str(md, node, str, data);
 			break;
 		case MD_PROP_DATA:
```