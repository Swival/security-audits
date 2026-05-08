# HID usage table wildcard name is used as snprintf format

## Classification

Memory corruption, medium severity.

## Affected Locations

`lib/libusbhid/usage.c:214`

`lib/libusbhid/usage.c:237`

## Summary

An attacker-controlled HID usage table wildcard name is stored by `hid_start()` and later passed as the format string to `snprintf()` in `hid_usage_in_page()`. Because the table string controls the format argument while only one integer variadic argument is supplied, conversions such as `%s`, `%p`, and `%n` can trigger crashes, memory disclosure, or undefined memory writes.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The victim process loads an attacker-controlled HID usage table through `hid_start()`.

## Proof

`hid_start()` parses wildcard usage entries with:

```c
sscanf(line, " * %99[^\n]", name)
```

Those entries are stored with `usage == -1` in `page_contents[j].name`.

Later, `hid_usage_in_page()` handles wildcard entries with:

```c
snprintf(b, sizeof b,
    pages[k].page_contents[j].name, i);
```

This makes the attacker-controlled wildcard name the `snprintf()` format string.

A table containing:

```text
1 Page
 * %s
```

reaches the vulnerable call when `hid_usage_in_page((1u << 16) | 1u)` is invoked. The `%s` conversion interprets the integer HID usage value as a pointer and crashes the process.

A wildcard such as `%p_%p_%p_%p` also causes `snprintf()` to consume missing variadic arguments and return process pointer-like values through the static buffer.

`%n` is source-level reachable and invokes undefined behavior with memory-write semantics because the format string is attacker-controlled and no matching pointer argument is supplied.

## Why This Is A Real Bug

The vulnerable path is direct and data-dependent only on a loaded HID usage table:

- `hid_start()` accepts wildcard names from the table file.
- The name is duplicated and retained without escaping or format validation.
- Wildcard entries are identified by `usage == -1`.
- `hid_usage_in_page()` passes the retained name as the `snprintf()` format string.
- Reproduction confirmed both segmentation fault with `%s` and pointer disclosure-like output with `%p_%p_%p_%p`.

This is not a cosmetic formatting issue; attacker-controlled bytes reach a variadic formatting sink as the format string.

## Fix Requirement

Do not use HID usage table strings as `printf`-family format strings. Wildcard names must be emitted as data, or alternatively strictly validated and escaped before use.

## Patch Rationale

The patch changes the wildcard path to call `snprintf()` with a fixed literal format:

```c
snprintf(b, sizeof b, "%s",
    pages[k].page_contents[j].name);
```

This preserves bounded copying into the static output buffer while ensuring conversion specifiers inside the attacker-controlled table entry are treated as ordinary text.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/libusbhid/usage.c b/lib/libusbhid/usage.c
index 5885994..4674f1c 100644
--- a/lib/libusbhid/usage.c
+++ b/lib/libusbhid/usage.c
@@ -234,8 +234,8 @@ hid_usage_in_page(unsigned int u)
 	for (j = 0; j < pages[k].pagesize; j++) {
 		us = pages[k].page_contents[j].usage;
 		if (us == -1) {
-			snprintf(b, sizeof b,
-			    pages[k].page_contents[j].name, i);
+			snprintf(b, sizeof b, "%s",
+			    pages[k].page_contents[j].name);
 			return b;
 		}
 		if (us == i)
```