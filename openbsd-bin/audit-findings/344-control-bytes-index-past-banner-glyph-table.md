# Control Bytes Index Past Banner Glyph Table

## Classification

Out-of-bounds read, medium severity.

## Affected Locations

`usr.sbin/lpd/lp_banner.c:1140`

## Summary

`lp_banner()` renders caller-supplied banner text by translating each byte with `TRC()` and indexing the static `scnkey` glyph table. Bytes below ASCII space map to indexes `96..127`, but `scnkey` only contains 96 glyphs for space through rub-out, indexed `0..95`. A submitted control byte in a banner field can therefore cause an out-of-bounds read past the global glyph table during banner printing.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

An attacker must be an accepted remote LPR client for the target queue.

The submitted print job must include a banner string containing at least one control byte below ASCII space.

Large banner printing must be enabled; the issue is reached through `L`, `J`, or `C` control-file banner fields when banners are not suppressed or replaced by short-banner mode.

## Proof

`scnkey` starts at `usr.sbin/lpd/lp_banner.c:116` and contains glyphs only for space through rub-out: 96 entries, valid indexes `0..95`.

`lp_banner()` processes each byte with:

```c
d = dropit(c = TRC(cc = *sp++));
...
strp = scnline(scnkey[(int)c][scnhgt-1-d], strp, cc);
```

`TRC(q)` is defined as:

```c
#define TRC(q) (((q)-' ')&0177)
```

For a submitted byte below space, such as `0x01`, `TRC(0x01)` computes an index in the range `96..127`. That index is then used directly as `scnkey[(int)c]`, reading beyond the 96-entry table.

The remote path is source-grounded: `frontend_lpr.c` receives raw control-file bytes and writes them unchanged, `engine_lpr.c` commits the job, then `printer.c` reads `L`, `J`, or `C` control-file lines into `job->literal`, `job->name`, or `job->class` and passes them to `lp_banner()` when large banners are enabled.

A submitted control-file line such as `L\x01\n` reaches `lp_banner()` and triggers the out-of-bounds read. An ASan harness calling `lp_banner(fd, "\001", 132)` aborts with `global-buffer-overflow` at `lp_banner.c:1137`, 9 bytes past `scnkey`.

## Why This Is A Real Bug

The banner string is attacker-controlled through a normal remote LPR job submission path.

No validation or normalization occurs before `lp_banner()` indexes `scnkey`.

The computed index can exceed the table bounds for any control byte below space.

ASan confirms a concrete global out-of-bounds read, not just a theoretical bounds mismatch.

## Fix Requirement

Reject or normalize bytes that translate outside the `scnkey` table before indexing it.

The index used for `scnkey[(int)c]` must always be constrained to the table’s valid range, `0..95`.

## Patch Rationale

The patch adds a bounds check immediately after `TRC()` computes the glyph index:

```c
if (c >= sizeof(scnkey) / sizeof(scnkey[0]))
	c = TRC(cc = ' ');
```

This preserves existing rendering for valid printable banner characters while normalizing invalid control-byte indexes to the space glyph.

Setting both `c` and `cc` keeps the glyph lookup and rendered character consistent: the banner emits blank space for invalid control input instead of using an out-of-range glyph index.

Using `sizeof(scnkey) / sizeof(scnkey[0])` ties the limit directly to the actual glyph table size and avoids hard-coding `96`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/lpd/lp_banner.c b/usr.sbin/lpd/lp_banner.c
index 6d363df..a5f93ab 100644
--- a/usr.sbin/lpd/lp_banner.c
+++ b/usr.sbin/lpd/lp_banner.c
@@ -1130,6 +1130,8 @@ lp_banner(int scfd, char *scsp, int pw)
 		sp = scsp;
 		for (nchrs = 0; ; ) {
 			d = dropit(c = TRC(cc = *sp++));
+			if (c >= sizeof(scnkey) / sizeof(scnkey[0]))
+				c = TRC(cc = ' ');
 			if ((!d && scnhgt > HEIGHT) || (scnhgt <= DROP && d))
 				for (j = WIDTH; --j;)
 					*strp++ = BACKGND;
```