# XMPP STARTTLS Response Writes Past Buffer

## Classification

Out-of-bounds write, medium severity.

## Affected Locations

`usr.bin/openssl/s_client.c:1314`

## Summary

`openssl s_client -starttls xmpp` reads an attacker-controlled XMPP STARTTLS response into an `8192` byte heap buffer and immediately writes a NUL terminator at `sbuf[seen]` without validating the returned length. If the server returns exactly `BUFSIZZ` bytes, `BIO_read()` returns `8192` and the terminator write lands one byte past the allocation. If `BIO_read()` returns `-1`, the write indexes before the buffer.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The client runs `s_client` with `-starttls xmpp` against an attacker-controlled XMPP server.

## Proof

- `-starttls xmpp` is reachable through `s_client_opt_starttls()`, which sets `cfg.starttls_proto = PROTO_XMPP`.
- `sbuf` is allocated with exactly `BUFSIZZ` bytes in `s_client_main()`.
- `BUFSIZZ` is `1024*8`, i.e. `8192`.
- In the `PROTO_XMPP` branch, after sending `<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>`, the client executes:
  ```c
  seen = BIO_read(sbio, sbuf, BUFSIZZ);
  sbuf[seen] = 0;
  ```
- An attacker-controlled XMPP server can send an `8192` byte response, causing `BIO_read(sbio, sbuf, BUFSIZZ)` to return `8192`.
- The subsequent write `sbuf[8192] = 0` writes one byte past the `8192` byte heap allocation.
- Runtime reproduction with a socket BIO confirmed `BIO_read(..., BUFSIZZ)` returned `8192`, and ASan reported a heap-buffer-overflow at the NUL write.

## Why This Is A Real Bug

The buffer size and read size are identical, but the code treats the buffer as a C string after the read. A full-length read leaves no room for the required NUL terminator. Because the server controls the response bytes and timing, the attacker can trigger the exact full-buffer read before the `<proceed` check runs. The result is attacker-triggered `s_client` denial of service or heap corruption.

## Fix Requirement

Require `0 <= seen < BUFSIZZ` before writing `sbuf[seen] = 0`.

## Patch Rationale

The patch rejects failed reads and full-buffer reads before NUL termination:

```c
seen = BIO_read(sbio, sbuf, BUFSIZZ);
if (seen < 0 || seen >= BUFSIZZ)
	goto shut;
sbuf[seen] = 0;
```

This preserves existing behavior for valid responses that fit with a trailing terminator, while preventing both negative indexing and the one-byte heap overflow on an exact `BUFSIZZ` response.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/openssl/s_client.c b/usr.bin/openssl/s_client.c
index 2b05fac..1bd9e2f 100644
--- a/usr.bin/openssl/s_client.c
+++ b/usr.bin/openssl/s_client.c
@@ -1315,6 +1315,8 @@ s_client_main(int argc, char **argv)
 		BIO_printf(sbio,
 		    "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
 		seen = BIO_read(sbio, sbuf, BUFSIZZ);
+		if (seen < 0 || seen >= BUFSIZZ)
+			goto shut;
 		sbuf[seen] = 0;
 		if (!strstr(sbuf, "<proceed"))
 			goto shut;
```