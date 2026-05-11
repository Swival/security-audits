# SSPI Decrypted Data Buffer Freed With Wrong Allocator

## Classification

Memory-safety / denial of service. Severity: medium.

Confidence: high.

## Affected Locations

`lib/vauth/krb5_sspi.c:310` (`Curl_auth_create_gssapi_security_message`, `FreeContextBuffer(input_buf[1].pvBuffer)`)

## Summary

`Curl_auth_create_gssapi_security_message` passes an attacker-controlled Kerberos SASL challenge to SSPI `DecryptMessage`, reads the decrypted four-byte security data from `input_buf[1].pvBuffer`, and then frees that pointer with `FreeContextBuffer`.

For SSPI Kerberos `DecryptMessage`, the decrypted data is exposed as a buffer view into caller-supplied message storage. It is not memory allocated by the security package. Calling `FreeContextBuffer` on it is therefore a wrong-allocator free that can terminate or corrupt the Windows client process.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

The finding was reproduced against the affected source path and confirmed to satisfy the claimed attacker, trigger, propagation path, failing operation, and denial-of-service impact.

## Preconditions

- Windows build with `USE_WINDOWS_SSPI` and `USE_KERBEROS5`.
- Client authenticates with Kerberos/GSSAPI to an attacker-controlled Kerberos-capable SASL server.
- Server sends a valid wrapped RFC4752 security message that decrypts to exactly four bytes.

## Proof

In `Curl_auth_create_gssapi_security_message`, the challenge buffer is installed as the SSPI stream input:

```c
input_buf[0].BufferType = SECBUFFER_STREAM;
input_buf[0].pvBuffer = CURL_UNCONST(Curl_bufref_ptr(chlg));
input_buf[0].cbBuffer = curlx_uztoul(Curl_bufref_len(chlg));
input_buf[1].BufferType = SECBUFFER_DATA;
input_buf[1].pvBuffer = NULL;
input_buf[1].cbBuffer = 0;
```

The code then calls `DecryptMessage`:

```c
status = Curl_pSecFn->DecryptMessage(krb5->context, &input_desc, 0, &qop);
```

On success, it accepts only a four-byte decrypted security payload:

```c
if(input_buf[1].cbBuffer != 4) {
  infof(data, "GSSAPI handshake failure (invalid security data)");
  return CURLE_BAD_CONTENT_ENCODING;
}
```

It reads the decrypted security layer and maximum message size from `input_buf[1].pvBuffer`:

```c
indata = input_buf[1].pvBuffer;
sec_layer = indata[0];
max_size = ((unsigned long)indata[1] << 16) |
           ((unsigned long)indata[2] << 8) | indata[3];
```

The vulnerable code then releases that pointer with the SSPI package allocator API:

```c
Curl_pSecFn->FreeContextBuffer(input_buf[1].pvBuffer);
```

`DecryptMessage` decrypts in place for the Kerberos package and returns decrypted data through the `SECBUFFER_DATA` output descriptor as a view into the caller-supplied challenge buffer. The pointer is not allocated by SSPI for ownership by the caller. A valid attacker-provided wrapped four-byte challenge therefore reaches a deterministic invalid free.

## Why This Is A Real Bug

`FreeContextBuffer` is only valid for buffers allocated by the SSPI security package and intended to be released by the caller. For Kerberos `DecryptMessage` invoked with `SECBUFFER_STREAM` + `SECBUFFER_DATA`, the `SECBUFFER_DATA` output typically aliases the caller's input buffer (in-place decryption) rather than a separately allocated package buffer. Calling `FreeContextBuffer` on such a pointer is a wrong-allocator free.

The attacker controls the server-side SASL challenge after authentication and can provide a valid wrapped four-byte RFC 4752 security message. That satisfies the code's length check and reaches the wrong-allocator `FreeContextBuffer` call. The observable consequence depends on the SSPI implementation: on current Windows the call typically returns an error harmlessly, but on builds or configurations where it touches the underlying heap, it can abort the process. Removing the call is correct regardless because, if SSPI did own the pointer, the only downside is a small one-time leak per authentication.

## Fix Requirement

Remove the `FreeContextBuffer(input_buf[1].pvBuffer)` call. Do not free pointers returned by `DecryptMessage` in this path because they do not transfer ownership to the caller.

## Patch Rationale

The patch deletes the invalid deallocation and leaves the decrypted data as a borrowed view into the input challenge buffer.

No replacement free is needed:
- `input_buf[1].pvBuffer` is not owned by this function.
- The original challenge lifetime remains managed by the existing `struct bufref` owner.
- Other locally allocated buffers in the function remain freed through the existing `out:` cleanup path.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/vauth/krb5_sspi.c b/lib/vauth/krb5_sspi.c
index e7491be022..2a42a64064 100644
--- a/lib/vauth/krb5_sspi.c
+++ b/lib/vauth/krb5_sspi.c
@@ -306,9 +306,6 @@ CURLcode Curl_auth_create_gssapi_security_message(struct Curl_easy *data,
   max_size = ((unsigned long)indata[1] << 16) |
              ((unsigned long)indata[2] << 8) | indata[3];
 
-  /* Free the challenge as it is not required anymore */
-  Curl_pSecFn->FreeContextBuffer(input_buf[1].pvBuffer);
-
   /* Process the security layer */
   if(!(sec_layer & KERB_WRAP_NO_ENCRYPT)) {
     infof(data, "GSSAPI handshake failure (invalid security layer)");
```