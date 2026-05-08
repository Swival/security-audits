# data property length permits out-of-bounds copy

## Classification

Denial of service, medium severity, confirmed.

## Affected Locations

`usr.sbin/ldomctl/mdesc.c:481`

## Summary

`md_ingest()` trusted `MD_PROP_DATA` element `data_offset` and `data_len` fields from an input machine description file. A crafted file could point a data property outside the declared data block, causing `md_add_data()` to copy from an out-of-bounds source pointer and crash `ldomctl`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`ldomctl` reads an attacker-controlled machine description file.

## Proof

A crafted MD file with a valid transport version, one node, one `MD_PROP_DATA`, valid name strings, `data_blk_sz = 0`, `data_offset = 0x7fffffff`, and `data_len = 1` passes the existing structural checks.

Execution reaches:

- `md_read()` loads the file into memory and calls `md_ingest()`.
- `md_ingest()` derives `data_blk` from attacker-controlled block sizes.
- For `MD_PROP_DATA`, `md_ingest()` computes `data = data_blk + betoh32(mde->d.y.data_offset)` without validating the offset.
- `md_ingest()` passes `betoh32(mde->d.y.data_len)` to `md_add_prop_data()` without validating the length.
- `md_add_prop_data()` forwards the unchecked pointer and length to `md_add_data()`.
- `md_add_data()` executes `memcpy(data->data, b, len)`, reading outside the MD buffer and crashing the process.

The reproduced stack reaches:

`md_read -> md_ingest -> md_add_prop_data -> md_add_data -> memcpy`

## Why This Is A Real Bug

The parser validates the aggregate file size against the declared block sizes, but it does not validate that each `MD_PROP_DATA` range is contained within the declared data block. Pointer arithmetic using an unchecked `data_offset` can produce an address outside the mapped input buffer, and `memcpy()` then dereferences that attacker-selected out-of-bounds range. This is a concrete denial-of-service condition for crafted local input.

## Fix Requirement

Before copying a data property, validate that:

- `data_offset <= data_blk_size`
- `data_len <= data_blk_size - data_offset`

Reject the machine description as corrupt if either condition fails.

## Patch Rationale

The patch adds a containment check in the `MD_PROP_DATA` case before computing the data pointer and before calling `md_add_prop_data()`. The subtraction is performed only after confirming `data_offset <= data_blk_size`, avoiding unsigned underflow. This ensures the copied range is entirely inside the declared data block.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ldomctl/mdesc.c b/usr.sbin/ldomctl/mdesc.c
index 3cae1f7..a111c34 100644
--- a/usr.sbin/ldomctl/mdesc.c
+++ b/usr.sbin/ldomctl/mdesc.c
@@ -476,6 +476,10 @@ md_ingest(void *buf, size_t size)
 		case MD_PROP_DATA:
 			if (node == NULL)
 				errx(1, "Corrupt MD");
+			if (betoh32(mde->d.y.data_offset) > data_blk_size ||
+			    betoh32(mde->d.y.data_len) > data_blk_size -
+			    betoh32(mde->d.y.data_offset))
+				errx(1, "Corrupt MD");
 			str = name_blk + betoh32(mde->name_offset);
 			data = data_blk + betoh32(mde->d.y.data_offset);
 			md_add_prop_data(md, node, str, data,
```