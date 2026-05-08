# Time Validator Ignores Bytes After NUL

## Classification

Policy bypass, medium severity.

## Affected Locations

`usr.sbin/ldapd/syntax.c:311`

## Summary

The LDAP Generalized Time and UTC Time syntax validators accept values that contain a valid time prefix followed by a NUL byte and attacker-controlled trailing bytes. The parser treats the value as a C string and validates only up to the first `'\0'`, while LDAP attribute values are length-delimited and may preserve bytes after NUL.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A writable Generalized Time or UTC Time attribute reaches the LDAP schema syntax validator.

## Proof

`syntax_is_gentime()` and `syntax_is_utctime()` both call `syntax_is_time()` in `usr.sbin/ldapd/syntax.c`.

Before the patch, `syntax_is_time()`:

- Received `char *value` and `size_t len`.
- Parsed using `char *p = value`.
- Did not bound parsing against `len`.
- Accepted the value with `return *p == '\0';`.

Therefore, a length-delimited LDAP attribute such as:

```text
20250101000000Z\0XYZ
```

is accepted as Generalized Time when `len` includes `XYZ`, because parsing stops at the embedded NUL after the valid `20250101000000Z` prefix.

Likewise:

```text
250101000000Z\0XYZ
```

is accepted as UTC Time.

The reproduced behavior confirmed both malformed values returned valid in a local harness copying `syntax_is_time()`. BER parsing preserves the original element length while appending an extra terminator, and serialized entries are later emitted using element lengths, so the trailing bytes after NUL remain present.

## Why This Is A Real Bug

LDAP attribute values are length-delimited byte strings, not C strings. A syntax validator must validate exactly the bytes supplied for the attribute value.

The previous implementation validated only the prefix before the first NUL and ignored remaining bytes included in `len`. This allows malformed attribute bytes to pass schema validation and be stored or returned despite not conforming to Generalized Time or UTC Time syntax.

## Fix Requirement

Validate exactly `len` bytes and accept only when the parser consumes the full supplied buffer.

Specifically:

- Track `end = value + len`.
- Check available bytes before reading fixed-width fields.
- Avoid dereferencing `p` when `p == end`.
- Replace NUL-based acceptance with `p == end`.

## Patch Rationale

The patch changes `syntax_is_time()` from C-string termination semantics to length-bounded parsing semantics.

It introduces:

```c
char *end = value + len;
```

and updates digit parsing to reject short buffers before reading `p[0]` and `p[1]`:

```c
if (end - p < 2 ||
    !isdigit((unsigned char)p[0]) ||
    !isdigit((unsigned char)p[1]))
        return 0;
```

All optional parsing checks now verify `p < end` before reading `*p`, and final acceptance now requires:

```c
return p == end;
```

This rejects values with embedded NUL followed by extra bytes because the parser stops at the NUL as a non-time character and no longer treats it as successful termination.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ldapd/syntax.c b/usr.sbin/ldapd/syntax.c
index de0eb8e..a22edaa 100644
--- a/usr.sbin/ldapd/syntax.c
+++ b/usr.sbin/ldapd/syntax.c
@@ -265,10 +265,12 @@ syntax_is_time(struct schema *schema, char *value, size_t len, int gen)
 {
 	int	 n;
 	char	*p = value;
+	char	*end = value + len;
 
 #define CHECK_RANGE(min, max) \
 	do {						\
-		if (!isdigit((unsigned char)p[0]) ||	\
+		if (end - p < 2 ||			\
+		    !isdigit((unsigned char)p[0]) ||	\
 		    !isdigit((unsigned char)p[1]))	\
 			return 0;			\
 		n = (p[0] - '0') * 10 + (p[1] - '0');	\
@@ -285,27 +287,27 @@ syntax_is_time(struct schema *schema, char *value, size_t len, int gen)
 	/* FIXME: should check number of days in month */
 	CHECK_RANGE(0, 23);			/* hour */
 
-	if (!gen || isdigit((unsigned char)*p)) {
+	if (!gen || (p < end && isdigit((unsigned char)*p))) {
 		CHECK_RANGE(0, 59);		/* minute */
-		if (isdigit((unsigned char)*p))
+		if (p < end && isdigit((unsigned char)*p))
 			CHECK_RANGE(0, 59+gen);	/* second or leap-second */
-		if (!gen && *p == '\0')
+		if (!gen && p == end)
 			return 1;
 	}
 						/* fraction */
-	if (!gen && ((*p == ',' || *p == '.') &&
-	    !isdigit((unsigned char)*++p)))
+	if (!gen && p < end && ((*p == ',' || *p == '.') &&
+	    (++p == end || !isdigit((unsigned char)*p))))
 		return 0;
 
-	if (*p == '-' || *p == '+') {
+	if (p < end && (*p == '-' || *p == '+')) {
 		++p;
 		CHECK_RANGE(0, 23);		/* hour */
-		if (!gen || isdigit((unsigned char)*p))
+		if (!gen || (p < end && isdigit((unsigned char)*p)))
 			CHECK_RANGE(0, 59);	/* minute */
-	} else if (*p++ != 'Z')
+	} else if (p == end || *p++ != 'Z')
 		return 0;
 
-	return *p == '\0';
+	return p == end;
 }
 
 static int
```