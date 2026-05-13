# malformed IP SAN causes out-of-bounds read

## Classification

Out-of-bounds read, medium severity.

Confidence: certain.

## Affected Locations

`src/boringssl/lib.rs:269`

## Summary

`ip2_string` treated every certificate IP subjectAltName whose length was not 4 bytes as IPv6. Malformed attacker-controlled IP SANs with lengths other than 4 or 16 therefore reached `c_ares::ntop(AF_INET6, ip.data, ...)` with a pointer to fewer than 16 bytes, violating the `inet_ntop` input contract and causing an out-of-bounds read during IP-literal hostname verification.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The client verifies a TLS peer hostname that is an IP literal.
- The malicious server presents a certificate chain that otherwise passes trust verification.
- The certificate contains a malformed `iPAddress` subjectAltName whose ASN.1 OCTET STRING length is neither 4 nor 16 bytes.

## Proof

`check_x509_server_identity` iterates certificate subjectAltName entries. For `GEN_IPADD`, when `host_ip` is present, it calls:

```rust
ip2_string(&*name.d.ip, &mut cert_ip_buf)
```

Before the patch, `ip2_string` selected IPv6 for all lengths except 4:

```rust
let af: c_int = if ip.length == 4 { AF_INET } else { AF_INET6 };
unsafe { c_ares::ntop(af, ip.data.cast(), &mut out_ip[..]) }
```

A concrete malicious SAN encoding such as `30 03 87 01 01` creates a `GENERAL_NAMES` sequence containing one `[7] iPAddress` value of length 1. For an IP-literal connection, this one-byte SAN reaches `ip2_string`, is classified as IPv6, and passes `ip.data` to `c_ares::ntop`.

The c-ares `AF_INET6` path requires `src` to point to a valid `in6_addr`, i.e. 16 bytes. The one-byte ASN.1 OCTET STRING does not satisfy that requirement, so IPv6 formatting reads beyond the SAN buffer.

## Why This Is A Real Bug

The malformed SAN is attacker-controlled certificate data. Local hostname verification did not reject invalid IP SAN lengths before entering the unsafe FFI call. The safety comment on the call required `ip.data` to reference 4 or 16 bytes, but the code only guaranteed the 4-byte case and allowed every other length to proceed as IPv6.

This creates memory-unsafe behavior in normal TLS hostname verification. Practical impact is denial of service: a malicious TLS server with a trusted chain can crash an IP-literal client during certificate identity checking.

## Fix Requirement

Reject IP subjectAltName values unless their ASN.1 OCTET STRING length is exactly:

- `4` bytes for IPv4.
- `16` bytes for IPv6.

Malformed lengths must not be passed to `c_ares::ntop`.

## Patch Rationale

The patch changes address-family selection from a two-way `if` to an explicit length match:

```rust
let af: c_int = match ip.length {
    4 => AF_INET,
    16 => AF_INET6,
    _ => return None,
};
```

This preserves valid IPv4 and IPv6 SAN handling while preventing malformed SANs from reaching the unsafe `ntop` call. Returning `None` treats the malformed SAN as non-matching, which is the correct behavior for an invalid certificate identifier.

The existing safety comment becomes true after the guard: `ip.data` is only passed to `ntop` when `ip.length` is 4 or 16.

## Residual Risk

None

## Patch

```diff
diff --git a/src/boringssl/lib.rs b/src/boringssl/lib.rs
index dabe83dab3..33245881ac 100644
--- a/src/boringssl/lib.rs
+++ b/src/boringssl/lib.rs
@@ -274,7 +274,11 @@ pub fn ip2_string<'a>(
     ip: &boring::ASN1_OCTET_STRING,
     out_ip: &'a mut [u8; INET6_ADDRSTRLEN + 1],
 ) -> Option<&'a [u8]> {
-    let af: c_int = if ip.length == 4 { AF_INET } else { AF_INET6 };
+    let af: c_int = match ip.length {
+        4 => AF_INET,
+        16 => AF_INET6,
+        _ => return None,
+    };
     // SAFETY: ip.data points to ip.length bytes (4 or 16); out_ip is INET6_ADDRSTRLEN+1 bytes.
     unsafe { c_ares::ntop(af, ip.data.cast(), &mut out_ip[..]) }
 }
```