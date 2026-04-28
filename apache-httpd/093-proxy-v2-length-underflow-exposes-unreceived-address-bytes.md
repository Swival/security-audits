# PROXY v2 length underflow exposes unreceived address bytes

## Classification

Memory safety; high severity; confidence certain.

## Affected Locations

`modules/metadata/mod_remoteip.c:716`

`modules/metadata/mod_remoteip.c:951`

`modules/metadata/mod_remoteip.c:956`

`modules/metadata/mod_remoteip.c:965`

`modules/metadata/mod_remoteip.c:1151`

`modules/metadata/mod_remoteip.c:1162`

## Summary

When PROXY protocol v2 handling is enabled, a peer can send a TCPv4 header whose v2 `len` is smaller than the required 12-byte IPv4 address block. The input filter trusts that length, stops reading at `16 + len`, and then processes the header as TCPv4. `remoteip_process_v2_header` reads source address and source port fields from the fixed header structure even though those bytes were never received.

The unreceived bytes can become `conn_conf->client_addr` and `conn_conf->client_ip`, which are later used as the request client address.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided source and patch evidence.

## Preconditions

- `RemoteIPProxyProtocol` is enabled for the connection.
- The peer sends a PROXY protocol v2 TCPv4 header.
- The peer-controlled v2 `len` is below the TCPv4 minimum address length of 12 bytes.

## Proof

The v2 length is read by `remoteip_get_v2_len` and used to set the amount of input required:

`ctx->need = MIN_V2_HDR_LEN + remoteip_get_v2_len((proxy_header *) ctx->header);`

Only a maximum-size check is applied before processing. If the supplied length is short, `ctx->need` becomes `16 + len`, and once `ctx->rcvd >= ctx->need`, the code calls:

`remoteip_process_v2_header(f->c, conn_conf, (proxy_header *) ctx->header);`

For TCPv4 family `0x11`, processing then reads:

- `hdr->v2.addr.ip4.src_port`
- `hdr->v2.addr.ip4.src_addr`

TCPv4 requires a 12-byte address block. With `len < 4`, some or all source-address bytes are unreceived. With `len < 10`, the source-port bytes are unreceived. The path does not need to read destination address or destination port to trigger the bug.

Those bytes are converted into `conn_conf->client_addr` and `conn_conf->client_ip`, and `remoteip_modify_request` later applies them as the request client address.

## Why This Is A Real Bug

The PROXY v2 `len` field is peer-controlled and is used as the completeness condition for the header. The parser accepts a TCPv4 family value but does not verify that the declared length contains the mandatory TCPv4 address structure before reading fields from it.

This creates a direct mismatch between received bytes and parsed bytes. On every enabled connection, before request handling, an attacker can cause the module to derive the client IP and port from bytes that were not part of the received PROXY header. That affects logging and any downstream IP-based authorization or application behavior relying on the client address.

## Fix Requirement

Validate the PROXY v2 family-specific minimum address lengths before reading address or port fields:

- TCPv4 must require at least `sizeof(hdr->v2.addr.ip4)` bytes.
- TCPv6 must require at least `sizeof(hdr->v2.addr.ip6)` bytes.
- Truncated headers must fail parsing with `HDR_ERROR`.

## Patch Rationale

The patch adds explicit minimum-length checks inside the TCPv4 and TCPv6 cases before any address or port fields are read.

For TCPv4, the parser now rejects `ntohs(hdr->v2.len) < sizeof(hdr->v2.addr.ip4)`, preventing reads of missing IPv4 source address or port bytes.

For TCPv6, the parser now rejects `ntohs(hdr->v2.len) < sizeof(hdr->v2.addr.ip6)`, applying the same invariant to the IPv6 address block.

The checks are placed at the use site, immediately before field access, so the parser cannot accidentally consume address-family data unless the declared and received header length is sufficient for that family.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/metadata/mod_remoteip.c b/modules/metadata/mod_remoteip.c
index 045e988..3171770 100644
--- a/modules/metadata/mod_remoteip.c
+++ b/modules/metadata/mod_remoteip.c
@@ -951,6 +951,11 @@ static remoteip_parse_status_t remoteip_process_v2_header(conn_rec *c,
         case 0x01: /* PROXY command */
             switch (hdr->v2.fam) {
                 case 0x11:  /* TCPv4 */
+                    if (ntohs(hdr->v2.len) < sizeof(hdr->v2.addr.ip4)) {
+                        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(10187)
+                                      "RemoteIPProxyProtocol: truncated IPv4 address");
+                        return HDR_ERROR;
+                    }
                     ret = apr_sockaddr_info_get(&conn_conf->client_addr, NULL,
                                                 APR_INET,
                                                 ntohs(hdr->v2.addr.ip4.src_port),
@@ -968,6 +973,11 @@ static remoteip_parse_status_t remoteip_process_v2_header(conn_rec *c,
 
                 case 0x21:  /* TCPv6 */
 #if APR_HAVE_IPV6
+                    if (ntohs(hdr->v2.len) < sizeof(hdr->v2.addr.ip6)) {
+                        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(10188)
+                                      "RemoteIPProxyProtocol: truncated IPv6 address");
+                        return HDR_ERROR;
+                    }
                     ret = apr_sockaddr_info_get(&conn_conf->client_addr, NULL,
                                                 APR_INET6,
                                                 ntohs(hdr->v2.addr.ip6.src_port),
```