# Unchecked name offset drives out-of-bounds string read

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`usr.sbin/ldomctl/mdesc.c:459`

## Summary

`md_ingest()` accepts attacker-controlled MD file contents and validates only aggregate block sizes before using `mde->name_offset` as an offset into the name block. If `name_offset` points outside `name_blk_size`, or points to bytes without an in-block NUL terminator, later string handling treats the resulting pointer as a C string and reads out of bounds. A crafted MD file can therefore crash `ldomctl` during parsing.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

`ldomctl` reads an attacker-crafted MD file supplied by a lower-privileged local user.

## Proof

`md_read()` loads the file into a heap buffer and calls `md_ingest()`.

In `md_ingest()`, the parser checks the transport version and aggregate block sizes, then derives:

```c
node_blk = (void *)mde;
name_blk = node_blk + node_blk_size;
data_blk = name_blk + name_blk_size;
```

For `MD_NODE`, the vulnerable flow is:

```c
str = name_blk + betoh32(mde->name_offset);
node = md_add_node(md, str);
```

`md_add_node()` calls `md_add_name()`, which calls `md_find_name()` and then `xstrdup(str)`. Those paths use `strcmp()` and `strdup()` on `str` as a NUL-terminated C string.

A reproduced ASan harness using committed `mdesc.c` and `util.c` with `name_blk_sz = 16` and `name_offset = 0x100000` crashes in `strlen/strdup`, reached through:

```text
md_ingest -> md_add_node -> md_add_name -> xstrdup
```

Existing checks at `usr.sbin/ldomctl/mdesc.c:438` and `usr.sbin/ldomctl/mdesc.c:446` do not verify `name_offset < name_blk_size` and do not verify that the referenced name is NUL-terminated within the name block.

## Why This Is A Real Bug

The MD file controls `mde->name_offset`. The parser converts that value into a pointer without bounds validation and passes it to string APIs that read until a NUL byte. When the offset is outside the name block, or when no NUL byte exists before the end of the name block, the read escapes the validated MD buffer. The reproduced ASan crash confirms attacker-controlled file input can terminate the parser.

## Fix Requirement

Before every use of `mde->name_offset` as a name string pointer, `md_ingest()` must verify:

```text
name_offset < name_blk_size
```

and must verify that a NUL byte exists between:

```text
name_blk + name_offset
```

and the end of the declared name block.

Invalid input must be rejected before calling `md_add_node()`, `md_add_prop_val()`, `md_add_prop_str()`, `md_add_prop_data()`, or `md_add_prop()`.

## Patch Rationale

The patch adds validation in every switch case that consumes `mde->name_offset`: `MD_NODE`, `MD_PROP_VAL`, `MD_PROP_STR`, `MD_PROP_DATA`, and `MD_PROP_ARC`.

For each case, it rejects offsets outside the name block:

```c
if (betoh32(mde->name_offset) >= name_blk_size)
	errx(1, "Corrupt MD");
```

It then checks that the selected string is NUL-terminated before the end of the name block:

```c
if (memchr(str, '\0',
    name_blk_size - betoh32(mde->name_offset)) == NULL)
	errx(1, "Corrupt MD");
```

This ensures later `strcmp()`, `strlen()`, and `strdup()` calls operate only on strings fully contained inside the validated name block.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ldomctl/mdesc.c b/usr.sbin/ldomctl/mdesc.c
index 3cae1f7..74a47fa 100644
--- a/usr.sbin/ldomctl/mdesc.c
+++ b/usr.sbin/ldomctl/mdesc.c
@@ -456,27 +456,47 @@ md_ingest(void *buf, size_t size)
 	for (index = 0; index < node_blk_size / sizeof(*mde); index++, mde++) {
 		switch(mde->tag) {
 		case MD_NODE:
+			if (betoh32(mde->name_offset) >= name_blk_size)
+				errx(1, "Corrupt MD");
 			str = name_blk + betoh32(mde->name_offset);
+			if (memchr(str, '\0',
+			    name_blk_size - betoh32(mde->name_offset)) == NULL)
+				errx(1, "Corrupt MD");
 			node = md_add_node(md, str);
 			node->index = index;
 			break;
 		case MD_PROP_VAL:
 			if (node == NULL)
 				errx(1, "Corrupt MD");
+			if (betoh32(mde->name_offset) >= name_blk_size)
+				errx(1, "Corrupt MD");
 			str = name_blk + betoh32(mde->name_offset);
+			if (memchr(str, '\0',
+			    name_blk_size - betoh32(mde->name_offset)) == NULL)
+				errx(1, "Corrupt MD");
 			md_add_prop_val(md, node, str, betoh64(mde->d.val));
 			break;
 		case MD_PROP_STR:
 			if (node == NULL)
 				errx(1, "Corrupt MD");
+			if (betoh32(mde->name_offset) >= name_blk_size)
+				errx(1, "Corrupt MD");
 			str = name_blk + betoh32(mde->name_offset);
+			if (memchr(str, '\0',
+			    name_blk_size - betoh32(mde->name_offset)) == NULL)
+				errx(1, "Corrupt MD");
 			data = data_blk + betoh32(mde->d.y.data_offset);
 			md_add_prop_str(md, node, str, data);
 			break;
 		case MD_PROP_DATA:
 			if (node == NULL)
 				errx(1, "Corrupt MD");
+			if (betoh32(mde->name_offset) >= name_blk_size)
+				errx(1, "Corrupt MD");
 			str = name_blk + betoh32(mde->name_offset);
+			if (memchr(str, '\0',
+			    name_blk_size - betoh32(mde->name_offset)) == NULL)
+				errx(1, "Corrupt MD");
 			data = data_blk + betoh32(mde->d.y.data_offset);
 			md_add_prop_data(md, node, str,
 			    betoh32(mde->d.y.data_len));
@@ -484,7 +504,12 @@ md_ingest(void *buf, size_t size)
 		case MD_PROP_ARC:
 			if (node == NULL)
 				errx(1, "Corrupt MD");
+			if (betoh32(mde->name_offset) >= name_blk_size)
+				errx(1, "Corrupt MD");
 			str = name_blk + betoh32(mde->name_offset);
+			if (memchr(str, '\0',
+			    name_blk_size - betoh32(mde->name_offset)) == NULL)
+				errx(1, "Corrupt MD");
 			prop = md_add_prop(md, node, str);
 			prop->tag = MD_PROP_ARC;
 			prop->d.arc.index = betoh64(mde->d.val);
```