# Unauthenticated AH Packets Consume SA Byte Lifetime

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

`netinet/ip_ah.c:605`

## Summary

Inbound AH packet byte accounting occurs before AH authenticator verification. A remote attacker can send AH packets with valid length fields but invalid authenticators and still advance `tdb->tdb_cur_bytes`. When byte lifetime enforcement is enabled, forged unauthenticated packets can trigger hard expiration, call `pfkeyv2_expire()`, delete the SA with `tdb_delete()`, and cause IPsec denial of service.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Target has an inbound AH SA.
- The SA has byte lifetime enforcement enabled with `TDBF_BYTES`.
- Attacker can send crafted AH packets matching the SA selector/SPI path sufficiently to reach `ah_input()`.

## Proof

In `ah_input()`, the replay precheck and AH length validation run before byte accounting:

- Replay precheck occurs before authentication and uses `checkreplaywindow(..., 0)`, so with replay enabled it does not commit the sequence number.
- AH header length and mbuf length are validated before accounting.
- `tdb_cur_bytes` is incremented from packet length before cryptographic verification.
- Hard byte lifetime enforcement immediately follows the increment.
- The crypto calculation and `timingsafe_bcmp()` authenticator comparison occur later.

The vulnerable ordering allows this sequence:

```text
forged AH packet
  -> passes replay precheck and AH length checks
  -> increments tdb->tdb_cur_bytes
  -> crosses tdb->tdb_exp_bytes
  -> pfkeyv2_expire(tdb, SADB_EXT_LIFETIME_HARD)
  -> tdb_delete(tdb)
  -> packet is dropped before authenticator rejection
```

Authentication is only enforced later by `timingsafe_bcmp()`, after the SA may already have been expired and deleted.

## Why This Is A Real Bug

AH authentication is intended to ensure unauthenticated packets do not affect protected SA state. Here, unauthenticated traffic mutates byte lifetime state and can trigger irreversible hard expiration. Because the replay precheck is non-committing, an attacker can reuse future/nonzero sequence values on forged packets until an authenticated packet commits replay state elsewhere. The impact is a remote-triggered deletion of a valid IPsec SA, causing denial of service for protected traffic.

## Fix Requirement

Move inbound AH byte accounting and byte lifetime checks until after the AH authenticator has been computed and successfully compared with `timingsafe_bcmp()`.

## Patch Rationale

The patch removes byte accounting, hard expiration, and soft expiration notification from the pre-authentication path and re-inserts the same logic immediately after the authenticator comparison succeeds.

This preserves existing byte lifetime behavior for valid AH packets while ensuring invalid authenticators cannot:

- increase `tdb->tdb_cur_bytes`;
- update inbound byte statistics;
- trigger soft lifetime notifications;
- trigger hard lifetime expiration;
- delete the SA.

## Residual Risk

None

## Patch

```diff
diff --git a/netinet/ip_ah.c b/netinet/ip_ah.c
index 9554aa9..e89172b 100644
--- a/netinet/ip_ah.c
+++ b/netinet/ip_ah.c
@@ -605,32 +605,6 @@ ah_input(struct mbuf **mp, struct tdb *tdb, int skip, int protoff,
 		goto drop;
 	}
 
-	/* Update the counters. */
-	ibytes = (m->m_pkthdr.len - skip - hl * sizeof(u_int32_t));
-	tdb->tdb_cur_bytes += ibytes;
-	tdbstat_add(tdb, tdb_ibytes, ibytes);
-	ahstat_add(ahs_ibytes, ibytes);
-
-	/* Hard expiration. */
-	if ((tdb->tdb_flags & TDBF_BYTES) &&
-	    (tdb->tdb_cur_bytes >= tdb->tdb_exp_bytes)) {
-		ipsecstat_inc(ipsec_exctdb);
-		pfkeyv2_expire(tdb, SADB_EXT_LIFETIME_HARD);
-		tdb_delete(tdb);
-		goto drop;
-	}
-
-	/* Notify on expiration. */
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
 	/* Get crypto descriptors. */
 	crp = crypto_getreq(1);
 	if (crp == NULL) {
@@ -714,5 +688,31 @@ ah_input(struct mbuf **mp, struct tdb *tdb, int skip, int protoff,
 		goto drop;
 	}
 
+	/* Update the counters. */
+	ibytes = (m->m_pkthdr.len - skip - hl * sizeof(u_int32_t));
+	tdb->tdb_cur_bytes += ibytes;
+	tdbstat_add(tdb, tdb_ibytes, ibytes);
+	ahstat_add(ahs_ibytes, ibytes);
+
+	/* Hard expiration. */
+	if ((tdb->tdb_flags & TDBF_BYTES) &&
+	    (tdb->tdb_cur_bytes >= tdb->tdb_exp_bytes)) {
+		ipsecstat_inc(ipsec_exctdb);
+		pfkeyv2_expire(tdb, SADB_EXT_LIFETIME_HARD);
+		tdb_delete(tdb);
+		goto drop;
+	}
+
+	/* Notify on expiration. */
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
 	/* Fix the Next Protocol field. */
 	ptr[protoff] = ptr[skip];
```