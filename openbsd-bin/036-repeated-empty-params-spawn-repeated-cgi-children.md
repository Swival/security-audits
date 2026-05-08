# Repeated Empty Params Spawn Repeated CGI Children

## Classification

Denial of service, high severity, certain confidence.

## Affected Locations

`usr.sbin/bgplgd/slowcgi.c:761`

## Summary

A FastCGI peer with access to the bgplgd FastCGI Unix socket can send repeated zero-length `FCGI_PARAMS` records for the same request. Each empty params record is treated as end-of-params and re-enters `exec_cgi(c)`, spawning additional `bgpctl` children and allocating pipes/events for a single logical request.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The attacker can connect to the FastCGI Unix socket.
- The attacker sends a valid `FCGI_BEGIN_REQUEST`.
- The attacker supplies params that make `prep_request()` accept the request, such as a valid `GET` to a known path.
- The attacker then sends repeated empty `FCGI_PARAMS` records with the same request id.

## Proof

`parse_params()` accepts attacker-controlled FastCGI records after `FCGI_BEGIN_REQUEST` if the request id matches.

At `usr.sbin/bgplgd/slowcgi.c:745`, every zero-length `FCGI_PARAMS` record is interpreted as end-of-params:

```c
if (n == 0) {
	exec_cgi(c);
	return;
}
```

No per-request flag records that CGI execution has already started. Therefore, repeated empty params records for the same request repeatedly call `exec_cgi(c)`.

Each `exec_cgi(c)` invocation:

- Calls `prep_request()`, which can succeed for valid request params.
- Creates three pipes at `usr.sbin/bgplgd/slowcgi.c:960`.
- Forks at `usr.sbin/bgplgd/slowcgi.c:969`.
- Runs `bgpctl_call()` in the child, which reaches `execvp()` at `usr.sbin/bgplgd/bgplgd.c:122`.
- Overwrites `command_pid` and script events for the same request, leaving prior child state no longer tracked by the request.

Repeated re-entry can exhaust processes or file descriptors. Pipe allocation failure calls fatal `lerr(1, "pipe")`, making daemon exit a practical outcome.

## Why This Is A Real Bug

FastCGI permits exactly one params stream terminator per request. The daemon begins CGI execution on that terminator but does not transition the request into an execution-started state. Because parsing continues on the same connection and request id, the attacker can replay the terminator and trigger side effects that should occur once.

The impact is not theoretical: each replay performs kernel resource allocation and process creation. The code also loses track of prior child/event state by overwriting request fields, worsening cleanup and making resource exhaustion reachable from a socket client.

## Fix Requirement

Add per-request state indicating that CGI execution has already started, set it before the first `exec_cgi(c)` call, and reject subsequent empty `FCGI_PARAMS` records for the same request.

## Patch Rationale

The patch adds `request_exec_started` to `struct request` and checks it in the zero-length `FCGI_PARAMS` path. The first empty params record sets the flag and starts CGI execution. Later empty params records are logged and ignored, preventing repeated `exec_cgi(c)` re-entry for one request.

Because request structs are allocated with `calloc()`, the new flag is initialized to zero with existing allocation behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/bgplgd/slowcgi.c b/usr.sbin/bgplgd/slowcgi.c
index 65cc1bd..c188f45 100644
--- a/usr.sbin/bgplgd/slowcgi.c
+++ b/usr.sbin/bgplgd/slowcgi.c
@@ -120,6 +120,7 @@ struct request {
 	int				script_flags;
 	uint16_t			id;
 	uint8_t				request_started;
+	uint8_t				request_exec_started;
 	uint8_t				request_done;
 	uint8_t				timeout_fired;
 };
@@ -743,6 +744,11 @@ parse_params(uint8_t *buf, uint16_t n, struct request *c, uint16_t id)
 	 * begin execution of the CGI script.
 	 */
 	if (n == 0) {
+		if (c->request_exec_started) {
+			lwarnx("unexpected FCGI_PARAMS, ignoring");
+			return;
+		}
+		c->request_exec_started = 1;
 		exec_cgi(c);
 		return;
 	}
```