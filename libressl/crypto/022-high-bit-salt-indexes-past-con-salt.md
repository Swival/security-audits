# High-Bit Salt Indexes Past con_salt

## Classification

Out-of-bounds read, medium severity.

## Affected Locations

`des/des_fcrypt.c:185`

## Summary

`DES_fcrypt()` uses the first two salt bytes as indexes into `con_salt`, but `con_salt` has only 128 entries. High-bit salt bytes are not constrained before indexing, so attacker-controlled salt can read outside the table and abort hashing under sanitizers or hardened runtimes.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Caller passes attacker-controlled salt to `DES_fcrypt()`.

## Proof

`con_salt` is declared as a 128-byte table in `des/des_fcrypt.c`.

Before the patch, `DES_fcrypt()` assigned `salt[0]` and `salt[1]` through `ret` into unsigned integer `x`, then immediately evaluated:

```c
Eswap0 = con_salt[x] << 2;
Eswap1 = con_salt[x] << 6;
```

No check constrained `x` to `0..127`.

A high-bit salt byte is sufficient:

- With signed `char`, `0x80` converts through `char` to a negative value and then to a large `unsigned int`, e.g. `4294967168`.
- With unsigned `char`, `0x80` becomes `128`.
- Both values are outside the valid `con_salt` index range.

A sanitizer harness calling:

```c
DES_fcrypt("pw", "\x80A", out);
```

reported:

```text
index 4294967168 out of bounds for type 'const unsigned char[128]'
```

at `des/des_fcrypt.c`, then aborted on the read.

The public API exposes `DES_fcrypt(const char *buf, const char *salt, char *ret)` in `des/des.h`, so applications that pass remote or otherwise attacker-controlled DES crypt salts can trigger the failure before hashing completes.

## Why This Is A Real Bug

The table bound is fixed at 128 entries, but the index is derived directly from caller-controlled input. The function does not reject, normalize, or mask salt bytes above `127` before indexing. Therefore both implementation-defined `char` signedness cases produce invalid indexes for high-bit bytes, making the out-of-bounds read reachable through the public API.

## Fix Requirement

Salt bytes used as `con_salt` indexes must be converted to `unsigned char` and constrained to the valid table range before indexing. Values outside `0..127` must not reach `con_salt[x]`.

## Patch Rationale

The patch normalizes each salt byte independently before the table lookup:

```c
x = (unsigned char)((salt[0] == '\0') ? 'A' : salt[0]);
if (x >= sizeof(con_salt))
	x = 'A';
ret[0] = x;
```

and repeats the same logic for `salt[1]`.

This removes signed-`char` widening hazards, prevents indexes `>= 128`, preserves the existing NUL-salt fallback to `'A'`, and maps invalid high-bit salt bytes to a safe existing salt value before computing `Eswap0` and `Eswap1`.

## Residual Risk

None

## Patch

```diff
diff --git a/des/des_fcrypt.c b/des/des_fcrypt.c
index 2dd071f..e5b116c 100644
--- a/des/des_fcrypt.c
+++ b/des/des_fcrypt.c
@@ -187,9 +187,15 @@ DES_fcrypt(const char *buf, const char *salt, char *ret)
 	 * crypt to "*".  This was found when replacing the crypt in
 	 * our shared libraries.  People found that the disabled
 	 * accounts effectively had no passwd :-(. */
-	x = ret[0] = ((salt[0] == '\0') ? 'A' : salt[0]);
+	x = (unsigned char)((salt[0] == '\0') ? 'A' : salt[0]);
+	if (x >= sizeof(con_salt))
+		x = 'A';
+	ret[0] = x;
 	Eswap0 = con_salt[x] << 2;
-	x = ret[1] = ((salt[1] == '\0') ? 'A' : salt[1]);
+	x = (unsigned char)((salt[1] == '\0') ? 'A' : salt[1]);
+	if (x >= sizeof(con_salt))
+		x = 'A';
+	ret[1] = x;
 	Eswap1 = con_salt[x] << 6;
 /* EAY
 r=strlen(buf);
```