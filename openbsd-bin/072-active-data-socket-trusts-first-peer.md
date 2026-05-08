# Active Data Socket Trusts First Peer

## Classification

High severity authorization bypass.

## Affected Locations

`usr.bin/ftp/ftp.c:1682`

## Summary

In active FTP mode, the client opens a listening data socket, advertises it to the authenticated FTP server, and later accepts the first inbound TCP connection as the transfer peer. The accepted peer is not checked against the control connection peer address. A network attacker who reaches the advertised active data port before the server can become the data channel, read upload contents, or inject download contents.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The client uses active FTP mode.
- The advertised active FTP data port is reachable by an attacker.
- The attacker can connect to the advertised data port before the FTP server.

## Proof

`initconn()` creates and listens on the active data socket before transfer commands are issued, then advertises the selected address and port using `EPRT`, `PORT`, or `LPRT`.

`sendrequest()` and `recvrequest()` call `initconn()` before issuing `STOR` or `RETR`, then call `dataconn()` only after a preliminary server reply.

In active mode, `dataconn()` calls:

```c
s = accept(data, &from.sa, &fromlen);
```

It then closes the listener, assigns `data = s`, and returns:

```c
return (fdopen(data, lmode));
```

The accepted address in `from` is not compared to `hisctladdr`.

The trusted data stream is then used directly:

- Uploads write local file bytes to the accepted peer.
- Downloads read bytes from the accepted peer and write them to the local output file.

Therefore, the first host to connect to the advertised active data port becomes the data peer, even if it is not the authenticated FTP server.

## Why This Is A Real Bug

Active FTP data connections are expected from the FTP server associated with the authenticated control connection. The code records that peer in `hisctladdr`, but `dataconn()` accepts any first inbound connection and treats it as authoritative.

This breaks the trust boundary between the authenticated control server and unauthenticated network peers. The resulting impact is concrete:

- For uploads, the attacker receives file contents intended for the FTP server.
- For downloads, the attacker supplies file contents that the client writes locally.

The reproduced control flow confirms there is no committed source check rejecting a mismatched active data peer.

## Fix Requirement

Reject active data connections whose peer address does not match `hisctladdr`.

The check must occur immediately after `accept()` and before the accepted socket is assigned to `data` or exposed through `fdopen()`.

## Patch Rationale

The patch validates the accepted active data peer against the authenticated control peer address:

- Rejects mismatched address families.
- For IPv4, compares `from.sin.sin_addr.s_addr` with `hisctladdr.sin.sin_addr.s_addr`.
- For IPv6, compares `from.sin6.sin6_addr` with `hisctladdr.sin6.sin6_addr`.
- On mismatch, closes both the accepted socket and active listener, clears `data`, and returns `NULL`.

This prevents an attacker-controlled first connection from being used as the transfer channel.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ftp/ftp.c b/usr.bin/ftp/ftp.c
index c6832cc..905e2d4 100644
--- a/usr.bin/ftp/ftp.c
+++ b/usr.bin/ftp/ftp.c
@@ -1687,6 +1687,17 @@ dataconn(const char *lmode)
 		(void)close(data), data = -1;
 		return (NULL);
 	}
+	if (from.sa.sa_family != hisctladdr.sa.sa_family ||
+	    (from.sa.sa_family == AF_INET &&
+	    from.sin.sin_addr.s_addr != hisctladdr.sin.sin_addr.s_addr) ||
+	    (from.sa.sa_family == AF_INET6 &&
+	    memcmp(&from.sin6.sin6_addr, &hisctladdr.sin6.sin6_addr,
+	    sizeof(from.sin6.sin6_addr)) != 0)) {
+		warnx("data connection from wrong host");
+		(void)close(s);
+		(void)close(data), data = -1;
+		return (NULL);
+	}
 	(void)close(data);
 	data = s;
 	if (from.sa.sa_family == AF_INET) {
```