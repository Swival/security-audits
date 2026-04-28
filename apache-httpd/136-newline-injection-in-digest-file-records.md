# Newline Injection In Digest File Records

## Classification

Validation gap, medium severity. Confidence: certain.

## Affected Locations

- `support/htdigest.c:157`
- `support/htdigest.c:222`
- `support/htdigest.c:240`

## Summary

`htdigest` accepts username and realm values containing record delimiters. Those values are copied from command-line arguments and written directly into digest password-file records as `user:realm:hash`. An attacker who controls either field can inject CR/LF characters to terminate the current record and append attacker-controlled physical records.

Because Apache digest-file authentication parses each physical line independently as `user:realm:hash`, the injected line can become an actionable credential record.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Attacker controls the `username` or `realm` argument passed to `htdigest`.
- The generated or updated digest file is later deployed for Apache digest authentication.

## Proof

`support/htdigest.c` copies command-line arguments into local fields without rejecting CR, LF, or colon:

```c
apr_cpystrn(user, argv[4], sizeof(user));
apr_cpystrn(realm, argv[3], sizeof(realm));
```

and in update mode:

```c
apr_cpystrn(user, argv[3], sizeof(user));
apr_cpystrn(realm, argv[2], sizeof(realm));
```

`add_password()` then writes those fields directly into the digest file:

```c
apr_file_printf(f, "%s:%s:", user, realm);
```

A username such as:

```text
attacker
victim:staff:80a39343a95c807bea6e65d82d2e5054
```

can produce a file shape like:

```text
attacker
victim:staff:80a39343a95c807bea6e65d82d2e5054:staff:<digest-for-attacker-input>
```

Apache’s digest file reader parses each physical line as colon-delimited fields. For the injected line, it selects:

```text
80a39343a95c807bea6e65d82d2e5054
```

as the stored HA1 value for `victim` in realm `staff`, ignoring trailing fields. This makes the injected record usable for authentication with the attacker-chosen password corresponding to that HA1.

## Why This Is A Real Bug

This is not limited to cosmetic file corruption. The digest file format is line-oriented, and `htdigest` writes untrusted fields before the computed digest without escaping or validation. Embedded newlines create additional physical records, and Apache accepts those records during authentication.

Colon characters are also unsafe because they alter field boundaries in the `user:realm:hash` format. Username and realm must therefore reject both record delimiters and field delimiters before any password-file write.

## Fix Requirement

Reject invalid username and realm values before create or update mode writes any digest record.

Required rejected characters:

- `:`
- LF / newline
- CR / carriage return

## Patch Rationale

The patch adds a single validation helper:

```c
static int field_has_invalid_chars(const char *field)
{
    return strchr(field, ':') || strchr(field, LF) || strchr(field, CR);
}
```

It then validates the relevant command-line fields before copying or writing them:

- Create mode rejects invalid `argv[3]` realm and `argv[4]` username.
- Update mode rejects invalid `argv[2]` realm and `argv[3]` username.

On validation failure, `htdigest` emits an error and exits before opening or modifying the target digest file in create mode, and before creating the temporary update file in update mode.

This directly prevents both newline-based record injection and colon-based field-boundary confusion.

## Residual Risk

None

## Patch

```diff
diff --git a/support/htdigest.c b/support/htdigest.c
index 43f7054..e4132e8 100644
--- a/support/htdigest.c
+++ b/support/htdigest.c
@@ -128,6 +128,11 @@ static void putline(apr_file_t *f, char *l)
         apr_file_putc(l[x], f);
 }
 
+static int field_has_invalid_chars(const char *field)
+{
+    return strchr(field, ':') || strchr(field, LF) || strchr(field, CR);
+}
+
 
 static void add_password(const char *user, const char *realm, apr_file_t *f)
 {
@@ -222,6 +227,10 @@ int main(int argc, const char * const argv[])
     if (argc == 5) {
         if (strcmp(argv[1], "-c"))
             usage();
+        if (field_has_invalid_chars(argv[3]) || field_has_invalid_chars(argv[4])) {
+            apr_file_printf(errfile, "Username and realm may not contain ':' or newline characters.\n");
+            exit(1);
+        }
         rv = apr_file_open(&f, argv[2], APR_WRITE | APR_CREATE,
                            APR_OS_DEFAULT, cntxt);
         if (rv != APR_SUCCESS) {
@@ -240,6 +249,11 @@ int main(int argc, const char * const argv[])
     else if (argc != 4)
         usage();
 
+    if (field_has_invalid_chars(argv[2]) || field_has_invalid_chars(argv[3])) {
+        apr_file_printf(errfile, "Username and realm may not contain ':' or newline characters.\n");
+        exit(1);
+    }
+
     if (apr_temp_dir_get((const char**)&dirname, cntxt) != APR_SUCCESS) {
         apr_file_printf(errfile, "%s: could not determine temp dir\n",
                         argv[0]);
```