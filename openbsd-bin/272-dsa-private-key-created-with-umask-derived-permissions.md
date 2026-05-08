# DSA private key created with umask-derived permissions

## Classification

Information disclosure, medium severity.

## Affected Locations

`lib/libkeynote/keynote-keygen.c:241`

## Summary

The DSA private-key generation path wrote the private key with `fopen(argv[4], "w")`. When creating a new file, `fopen()` uses default create permissions equivalent to `0666` filtered only by the process umask. Under a permissive umask, the generated KeyNote private signing key could therefore be readable by other local users.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The victim generates a DSA private key with `keynote_keygen`.
- The victim chooses a new private key output path in a location searchable/readable by another local user.
- The victim process has a permissive umask, for example `022`.

## Proof

In the DSA path, `keynote_keygen()` encodes the private key using:

- `kn_encode_key(&dc, ienc, enc, KEYNOTE_PRIVATE_KEY)` at `lib/libkeynote/keynote-keygen.c:228`

That private key is then written to `argv[4]`. Before the patch, the private-key file was opened with:

```c
fp = fopen(argv[4], "w");
```

Because `fopen(..., "w")` creates new files with permissions derived from `0666 & ~umask`, a victim running with umask `022` could create the private key as `0644`.

The reproduced impact is that a lower-privileged local attacker can read the generated `private-dsa-*` KeyNote signing key from the victim-selected shared-readable path. The disclosed file is the same private key format consumed by signing code at `lib/libkeynote/keynote-sign.c:141`, allowing the attacker to copy the victim's signing key and sign as that principal.

## Why This Is A Real Bug

Private signing keys must not inherit broad filesystem permissions from the caller's umask. The affected path writes a freshly generated DSA private key, not public material, and there was no restrictive create mode, `chmod()`, or `fchmod()` applied after file creation.

A common umask such as `022` leaves newly created files world-readable. In an attacker-searchable parent directory, that exposes the private KeyNote signing key to local users.

## Fix Requirement

Create private key files with owner-only permissions at creation time.

The private key output path must be opened using a restrictive file mode such as `0600`, then converted to a `FILE *` stream for the existing `print_key()` logic.

## Patch Rationale

The patch replaces the DSA private-key `fopen(argv[4], "w")` call with:

```c
fd = open(argv[4], O_WRONLY | O_CREAT | O_TRUNC, 0600);
fp = fdopen(fd, "w");
```

This makes new private-key files owner-readable and owner-writable only, independent of permissive umask values. `fdopen()` preserves the existing stream-based write path. If `fdopen()` fails, the descriptor is closed before exiting, avoiding a descriptor leak.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/libkeynote/keynote-keygen.c b/lib/libkeynote/keynote-keygen.c
index edf013e..1c5eded 100644
--- a/lib/libkeynote/keynote-keygen.c
+++ b/lib/libkeynote/keynote-keygen.c
@@ -240,10 +240,19 @@ keynote_keygen(int argc, char *argv[])
 	}
 	else
 	{
-	    fp = fopen(argv[4], "w");
+	    int fd;
+
+	    fd = open(argv[4], O_WRONLY | O_CREAT | O_TRUNC, 0600);
+	    if (fd == -1)
+	    {
+		perror(argv[4]);
+		exit(1);
+	    }
+	    fp = fdopen(fd, "w");
 	    if (fp == NULL)
 	    {
 		perror(argv[4]);
+		close(fd);
 		exit(1);
 	    }
 	}
```