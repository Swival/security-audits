# Client PTR Forward Lookup Can Terminate Listener

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.bin/openssl/s_socket.c:258`

## Summary

A remote TCP client whose source address has an attacker-controlled PTR record can terminate an `openssl` server listener if that PTR hostname does not resolve to an IPv4 A record.

`do_accept()` accepts the TCP connection, performs a reverse DNS lookup, then treats forward DNS validation failure as fatal. The fatal `0` return propagates to `do_server()`, which closes the listening socket and exits the accept loop.

## Provenance

Verified from the supplied source, reproducer summary, and patch.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `openssl` server is running in TCP server mode.
- The server accepts clients through `do_server()`.
- Reverse DNS lookup is performed for connecting clients.
- An attacker can connect from an address whose PTR record resolves to a hostname lacking a forward IPv4 A record.

## Proof

`do_server()` accepts TCP clients through `do_accept()`:

- `usr.bin/openssl/s_socket.c:147` treats `do_accept(accept_socket, &sock) == 0` as fatal.
- On that path, `do_server()` shuts down and closes `accept_socket`, then returns `0`.

`do_accept()` accepts the client before DNS validation:

- `usr.bin/openssl/s_socket.c:238` calls `accept()`.
- `usr.bin/openssl/s_socket.c:249` calls `gethostbyaddr()` on the accepted client's source address.
- If PTR lookup succeeds, the returned hostname is duplicated and passed to `gethostbyname()`.
- At `usr.bin/openssl/s_socket.c:260`, if `gethostbyname(host)` returns `NULL`, the original code closes the accepted socket, frees `host`, and returns `0`.
- The same fatal return occurs if the forward lookup result is not `AF_INET`.

Therefore, one raw TCP connection from an address with a PTR hostname that lacks an A record can cause `do_server()` to close the listener before TLS handling and deny future clients.

## Why This Is A Real Bug

The failed forward DNS lookup is client-controlled and occurs after `accept()`, but before normal connection handling. The code conflates a per-client DNS validation failure with an accept-loop failure.

`do_server()` has no way to distinguish this DNS condition from a fatal listener error because `do_accept()` returns `0` for both. As a result, a single unauthenticated remote connection can terminate the listening server.

The reproduced flow confirms the impact:

- TCP server mode is used.
- Unlimited accepts are configured.
- `do_accept()` returns `0` on PTR forward lookup failure.
- `do_server()` closes `accept_socket` and exits immediately.

## Fix Requirement

Forward DNS validation failure for a client's PTR hostname must not be fatal to the listener.

Acceptable behavior is to either:

- continue handling the already accepted client, or
- close only that client socket and continue accepting future clients.

The listener socket must remain open unless `accept()` itself fails fatally or the configured accept limit/callback termination condition is reached.

## Patch Rationale

The patch makes PTR forward lookup failure nonfatal inside `do_accept()`.

When `gethostbyname(host)` fails, the code now logs `gethostbyname failure` but does not close the accepted socket and does not return `0`.

When the forward lookup succeeds but is not `AF_INET`, the code now logs `gethostbyname addr is not AF_INET` but does not close the accepted socket and does not return `0`.

This preserves the diagnostic behavior while preventing attacker-controlled DNS from terminating the accept loop.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/openssl/s_socket.c b/usr.bin/openssl/s_socket.c
index 86a23c5..e93fc54 100644
--- a/usr.bin/openssl/s_socket.c
+++ b/usr.bin/openssl/s_socket.c
@@ -260,15 +260,8 @@ do_accept(int acc_sock, int *sock)
 		h2 = gethostbyname(host);
 		if (h2 == NULL) {
 			BIO_printf(bio_err, "gethostbyname failure\n");
-			close(ret);
-			free(host);
-			return (0);
-		}
-		if (h2->h_addrtype != AF_INET) {
+		} else if (h2->h_addrtype != AF_INET) {
 			BIO_printf(bio_err, "gethostbyname addr is not AF_INET\n");
-			close(ret);
-			free(host);
-			return (0);
 		}
 	}
```