# CTF payload length includes header

## Classification

Out-of-bounds read, medium severity.

## Affected Locations

`usr.bin/ctfdump/ctfdump.c:278`

## Summary

`ctfdump` validates an uncompressed CTF file’s payload length against the full mapped file size instead of the file size minus the CTF header. A crafted raw CTF file can pass `isctf()` validation with `dlen == filesize`, then `ctf_dump()` treats offsets as relative to `p + sizeof(struct ctf_header)`, causing reads past the mapped file.

## Provenance

Verified from the supplied source, reproducer summary, and patch.

Scanner provenance: Swival Security Scanner, https://swival.dev

Confidence: certain.

## Preconditions

Victim runs `ctfdump` on attacker-controlled uncompressed CTF input.

## Proof

For non-ELF input, `dump()` maps the entire file and calls:

- `isctf(p, st.st_size)`
- `ctf_dump(p, st.st_size, flags)`

In `isctf()`, `dlen` is computed as:

```c
dlen = cth.cth_stroff + cth.cth_strlen;
```

Before the patch, uncompressed CTF input was accepted unless:

```c
dlen > filesize
```

However, `ctf_dump()` sets the uncompressed payload base to:

```c
data = (char *)p + sizeof(cth);
```

The reproducer uses a crafted raw CTF file where:

- `cth_flags = 0`
- `dlen == filesize`
- `cth_lbloff = cth_objtoff = cth_funcoff = cth_typeoff = N - 4`
- `cth_stroff = N`
- `cth_strlen = 0`
- `N` is the file size and 4-byte aligned

This passes the old `isctf()` bounds check because `dlen == filesize`.

Then the type dump loop enters because `offset < stroff`:

```c
while (offset < stroff) {
	ctf_dump_type(&cth, data, dlen, stroff, &offset, idx++);
}
```

Inside `ctf_dump_type()`, the crafted offset forms:

```c
const char *p = data + *offset;
const struct ctf_type *ctt = (struct ctf_type *)p;
```

With `data = file_base + sizeof(struct ctf_header)` and `*offset = N - 4`, this points past the mapped `[file_base, file_base + N)` file. The function then dereferences `ctt->ctt_info`, `ctt->ctt_name`, and related fields.

## Why This Is A Real Bug

The CTF header is not part of the payload address space used by `ctf_dump()`. Offsets are interpreted relative to `p + sizeof(struct ctf_header)`, but validation compared the payload length against the whole file mapping.

Therefore, for uncompressed files, the valid maximum payload length is:

```c
filesize - sizeof(struct ctf_header)
```

not:

```c
filesize
```

The reproduced input reaches an attacker-controlled out-of-bounds read in a mapped file parser. With a page-aligned file, the read can fault beyond the mapping and crash `ctfdump`, providing a concrete local attacker-controlled-file denial of service.

## Fix Requirement

For uncompressed CTF input, validate that the declared CTF payload length fits after the header:

```c
sizeof(struct ctf_header) + dlen <= filesize
```

Equivalently:

```c
dlen <= filesize - sizeof(struct ctf_header)
```

## Patch Rationale

The patch changes the uncompressed size check in `isctf()` from comparing `dlen` against the full file size to comparing it against the mapped payload capacity after the header:

```diff
-	if (dlen > filesize && !(cth.cth_flags & CTF_F_COMPRESS)) {
+	if (dlen > filesize - sizeof(struct ctf_header) &&
+	    !(cth.cth_flags & CTF_F_COMPRESS)) {
```

This aligns validation with `ctf_dump()`’s payload base:

```c
data = (char *)p + sizeof(cth);
```

A file where `dlen == filesize` is now rejected for uncompressed CTF because the payload would extend past the mapped file once the header is skipped.

## Residual Risk

None

## Patch

`280-ctf-payload-length-includes-header.patch`

```diff
diff --git a/usr.bin/ctfdump/ctfdump.c b/usr.bin/ctfdump/ctfdump.c
index 58a7907..709c7cf 100644
--- a/usr.bin/ctfdump/ctfdump.c
+++ b/usr.bin/ctfdump/ctfdump.c
@@ -286,7 +286,8 @@ isctf(const char *p, size_t filesize)
 		return 0;
 
 	dlen = cth.cth_stroff + cth.cth_strlen;
-	if (dlen > filesize && !(cth.cth_flags & CTF_F_COMPRESS)) {
+	if (dlen > filesize - sizeof(struct ctf_header) &&
+	    !(cth.cth_flags & CTF_F_COMPRESS)) {
 		warnx("bogus file size");
 		return 0;
 	}
```