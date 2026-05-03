# PAP accepts prefix credentials

## Classification

Authentication bypass, high severity.

## Affected Locations

`net/if_spppsubr.c:3816`

## Summary

The PAP verifier accepted attacker-supplied credential prefixes, including zero-length username and password fields, because it compared only the lengths supplied in the PAP request. A malicious PPP peer on a PAP-authenticated link could send an empty or prefix `PAP_REQ` and be accepted into PPP network phase without knowing the configured peer credentials.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The local endpoint is configured to authenticate the peer with PAP.

## Proof

In `sppp_pap_input`, the `PAP_REQ` handler parses attacker-controlled `name_len` and `passwd_len`, then bounds-checks them against the packet length and `AUTHMAXLEN`.

Before the patch, authentication failure was decided by:

```c
if (name_len > AUTHMAXLEN ||
    passwd_len > AUTHMAXLEN ||
    bcmp(name, sp->hisauth.name, name_len) != 0 ||
    bcmp(passwd, sp->hisauth.secret, passwd_len) != 0) {
```

There was no requirement that:

```c
name_len == strlen(sp->hisauth.name)
passwd_len == strlen(sp->hisauth.secret)
```

Therefore:

- `name_len=0` makes `bcmp(name, sp->hisauth.name, 0)` compare equal.
- `passwd_len=0` makes `bcmp(passwd, sp->hisauth.secret, 0)` compare equal.
- Any supplied prefix of the configured username and password also compares equal.

On success, the handler sends `PAP_ACK`, changes PAP to `STATE_OPENED`, calls `pap.tlu(sp)`, and `sppp_pap_tlu` can call `sppp_phase_network(sp)`, allowing the unauthenticated peer to reach PPP network negotiation.

Concrete trigger: with configured non-empty PAP peer credentials, send a `PAP_REQ` after PAP authentication is negotiated with `name_len=0` and `passwd_len=0`.

## Why This Is A Real Bug

PAP authentication must verify the complete configured username and password. Comparing only attacker-declared prefix lengths changes equality into prefix matching. Because zero-length `bcmp` succeeds, the weakest exploit does not require guessing any credential bytes.

The vulnerable path directly leads to authentication success behavior: `PAP_ACK`, `STATE_OPENED`, `pap.tlu`, and possible transition to `PHASE_NETWORK`.

## Fix Requirement

Require the supplied PAP username and password lengths to exactly equal the configured credential lengths before comparing credential bytes.

## Patch Rationale

The patch adds exact-length checks before `bcmp`:

```c
name_len != strlen(sp->hisauth.name) ||
passwd_len != strlen(sp->hisauth.secret) ||
```

This preserves the existing packet bounds checks and byte comparisons while preventing empty-string and prefix matches from being treated as valid credentials.

## Residual Risk

None

## Patch

```diff
diff --git a/net/if_spppsubr.c b/net/if_spppsubr.c
index 1ddc1ec..e089ec7 100644
--- a/net/if_spppsubr.c
+++ b/net/if_spppsubr.c
@@ -3815,6 +3815,8 @@ sppp_pap_input(struct sppp *sp, struct mbuf *m)
 		}
 		if (name_len > AUTHMAXLEN ||
 		    passwd_len > AUTHMAXLEN ||
+		    name_len != strlen(sp->hisauth.name) ||
+		    passwd_len != strlen(sp->hisauth.secret) ||
 		    bcmp(name, sp->hisauth.name, name_len) != 0 ||
 		    bcmp(passwd, sp->hisauth.secret, passwd_len) != 0) {
 			/* action scn, tld */
```