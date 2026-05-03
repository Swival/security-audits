# Unauthenticated ESP Bytes Expire Security Association

## Classification

Denial of service, high severity.

Confidence: certain.

## Affected Locations

`netinet/ip_esp.c:420`

## Summary

`esp_input()` charged inbound ESP payload bytes to `tdb->tdb_cur_bytes` before cryptographic authentication and before the replay-window commit check. If the SA had a hard byte lifetime enabled, forged ESP packets using the target SPI could inflate the byte counter until `tdb_delete()` deleted the SA. This let an unauthenticated remote attacker disrupt protected IPsec traffic.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and confirmed against the provided `netinet/ip_esp.c` source and patched by moving inbound byte accounting after successful authentication and replay validation.

## Preconditions

- The inbound ESP SA has byte hard lifetime enabled through `TDBF_BYTES`.
- The attacker can send ESP packets to the endpoint.
- The attacker knows or can guess the target SPI.
- The attacker does not need the authentication key.

## Proof

In the vulnerable flow:

- `esp_input()` computes `plen` from the received mbuf length.
- Before crypto completion or `timingsafe_bcmp()` authentication, it executes:
  - `tdb->tdb_cur_bytes += plen`
  - `tdbstat_add(tdb, tdb_ibytes, plen)`
  - `espstat_add(esps_ibytes, plen)`
- Immediately afterward, if `TDBF_BYTES` is set and `tdb_cur_bytes >= tdb_exp_bytes`, it calls:
  - `pfkeyv2_expire(tdb, SADB_EXT_LIFETIME_HARD)`
  - `tdb_delete(tdb)`
- Authentication failure is only detected later by `timingsafe_bcmp()` in `esp_input()`.
- `tdb_delete()` marks the SA deleted and unlinks it from the SADB, disrupting later protected traffic for that SA.

A remote attacker can therefore send repeated forged ESP packets with the target SPI and large payloads. These packets are unauthenticated, but their `plen` values are still charged against the SA hard byte lifetime before the packets are rejected.

## Why This Is A Real Bug

The byte lifetime is a property of traffic accepted by the SA, not arbitrary unauthenticated packets that merely name the SA SPI. Charging unauthenticated bytes lets an attacker consume a finite SA lifetime without proving possession of the SA keys.

The reproduced control flow shows the deletion path is reachable before authentication failure handling. The impact is concrete because `tdb_delete()` removes the SA from active use, causing denial of service for legitimate IPsec traffic.

## Fix Requirement

Charge inbound ESP byte lifetime only after the packet has passed authentication and replay checks. Invalid or unauthenticated packets must not advance `tdb_cur_bytes` or trigger hard or soft byte lifetime expiration.

## Patch Rationale

The patch removes the inbound byte accounting and lifetime expiration block from the pre-crypto path and reinserts it after:

- crypto processing completes,
- ESP authentication succeeds,
- the trailing authenticator is removed,
- replay-window checking with commit succeeds.

This preserves lifetime accounting for valid inbound ESP traffic while preventing forged unauthenticated packets from consuming the SA byte lifetime.

## Residual Risk

None

## Patch

```diff
diff --git a/netinet/ip_esp.c b/netinet/ip_esp.c
index 2f508b6..161728b 100644
--- a/netinet/ip_esp.c
+++ b/netinet/ip_esp.c
@@ -416,31 +416,6 @@ esp_input(struct mbuf **mp, struct tdb *tdb, int skip, int protoff,
 		}
 	}
 
-	/* Update the counters */
-	tdb->tdb_cur_bytes += plen;
-	tdbstat_add(tdb, tdb_ibytes, plen);
-	espstat_add(esps_ibytes, plen);
-
-	/* Hard expiration */
-	if ((tdb->tdb_flags & TDBF_BYTES) &&
-	    (tdb->tdb_cur_bytes >= tdb->tdb_exp_bytes))	{
-		ipsecstat_inc(ipsec_exctdb);
-		pfkeyv2_expire(tdb, SADB_EXT_LIFETIME_HARD);
-		tdb_delete(tdb);
-		goto drop;
-	}
-
-	/* Notify on soft expiration */
-	mtx_enter(&tdb->tdb_mtx);
-	if ((tdb->tdb_flags & TDBF_SOFT_BYTES) &&
-	    (tdb->tdb_cur_bytes >= tdb->tdb_soft_bytes)) {
-		tdb->tdb_flags &= ~TDBF_SOFT_BYTES;  /* Turn off checking */
-		mtx_leave(&tdb->tdb_mtx);
-		/* may sleep in solock() for the pfkey socket */
-		pfkeyv2_expire(tdb, SADB_EXT_LIFETIME_SOFT);
-	} else
-		mtx_leave(&tdb->tdb_mtx);
-
 	/* Get crypto descriptors */
 	crp = crypto_getreq(esph && espx ? 2 : 1);
 	if (crp == NULL) {
@@ -576,6 +551,31 @@ esp_input(struct mbuf **mp, struct tdb *tdb, int skip, int protoff,
 		}
 	}
 
+	/* Update the counters */
+	tdb->tdb_cur_bytes += plen;
+	tdbstat_add(tdb, tdb_ibytes, plen);
+	espstat_add(esps_ibytes, plen);
+
+	/* Hard expiration */
+	if ((tdb->tdb_flags & TDBF_BYTES) &&
+	    (tdb->tdb_cur_bytes >= tdb->tdb_exp_bytes))	{
+		ipsecstat_inc(ipsec_exctdb);
+		pfkeyv2_expire(tdb, SADB_EXT_LIFETIME_HARD);
+		tdb_delete(tdb);
+		goto drop;
+	}
+
+	/* Notify on soft expiration */
+	mtx_enter(&tdb->tdb_mtx);
+	if ((tdb->tdb_flags & TDBF_SOFT_BYTES) &&
+	    (tdb->tdb_cur_bytes >= tdb->tdb_soft_bytes)) {
+		tdb->tdb_flags &= ~TDBF_SOFT_BYTES;  /* Turn off checking */
+		mtx_leave(&tdb->tdb_mtx);
+		/* may sleep in solock() for the pfkey socket */
+		pfkeyv2_expire(tdb, SADB_EXT_LIFETIME_SOFT);
+	} else
+		mtx_leave(&tdb->tdb_mtx);
+
 	/* Find beginning of ESP header */
 	m1 = m_getptr(m, skip, &roff);
 	if (m1 == NULL)	{
```