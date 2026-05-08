# shortlist host prefix bypass

## Classification

Policy bypass, medium severity. Confidence: certain.

## Affected Locations

`usr.sbin/rpki-client/main.c:525`

## Summary

`rpki-client` shortlist mode (`-H`) can be bypassed because repository host matching compares only the attacker-controlled host prefix length. A malicious RPKI CA can publish a certificate whose repository host is a prefix of a shortlisted FQDN, causing an unshortlisted repository to be accepted, fetched, and processed.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

Operator enables shortlist mode with `-H`.

## Proof

In `queue_add_from_cert()`, the repository host is derived from attacker-controlled certificate data:

```c
host = cert->repo + RSYNC_PROTO_LEN;
```

The shortlist check compares using the length of `host` up to `/`:

```c
strncasecmp(host, le->fqdn, strcspn(host, "/")) == 0
```

Because the comparison length comes from the attacker-controlled repository host, a shorter host can match the prefix of a configured shortlist entry. For example:

```c
strncasecmp("rpki.cloud/...", "rpki.cloudflare.com", strlen("rpki.cloud")) == 0
```

This sets `shortlisted = 1`, skips the `shortlistmode` rejection, and allows the repository to reach `repo_lookup()`. The repository is then queued for RRDP or rsync fetching and processing.

## Why This Is A Real Bug

The documented `-H` policy says `rpki-client` only connects to shortlisted hosts. The vulnerable comparison permits hosts that are not equal to the configured FQDN, only prefixes of it. Since `cert->repo` is controlled by an RPKI CA through certificate SIA values, a malicious CA can intentionally select such a prefix host and cause `rpki-client` to connect to and process an unshortlisted repository.

## Fix Requirement

Compare complete hostnames by both length and case-insensitive contents. A host must match a shortlist or skiplist entry only when the host component length equals the configured FQDN length and the bytes compare equal case-insensitively.

## Patch Rationale

The patch computes the repository host component length once:

```c
hostsz = strcspn(host, "/");
```

It then requires `strlen(le->fqdn) == hostsz` before calling `strncasecmp()`. This prevents attacker-controlled short prefixes from matching longer configured entries while preserving case-insensitive exact FQDN matching.

The same correction is applied to both skiplist and shortlist matching, avoiding asymmetric behavior between allow and deny policy checks.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/rpki-client/main.c b/usr.sbin/rpki-client/main.c
index 26bb511..4a2a98b 100644
--- a/usr.sbin/rpki-client/main.c
+++ b/usr.sbin/rpki-client/main.c
@@ -517,22 +517,25 @@ queue_add_from_cert(const struct cert *cert, struct nca_tree *ncas)
 	struct fqdnlistentry	*le;
 	char			*nfile, *npath, *host;
 	const char		*uri, *repouri, *file;
-	size_t			 repourisz;
+	size_t			 repourisz, hostsz;
 	int			 shortlisted = 0;
 
 	if (strncmp(cert->repo, RSYNC_PROTO, RSYNC_PROTO_LEN) != 0)
 		errx(1, "unexpected protocol");
 	host = cert->repo + RSYNC_PROTO_LEN;
+	hostsz = strcspn(host, "/");
 
 	LIST_FOREACH(le, &skiplist, entry) {
-		if (strncasecmp(host, le->fqdn, strcspn(host, "/")) == 0) {
+		if (strlen(le->fqdn) == hostsz &&
+		    strncasecmp(host, le->fqdn, hostsz) == 0) {
 			warnx("skipping %s (listed in skiplist)", cert->repo);
 			return;
 		}
 	}
 
 	LIST_FOREACH(le, &shortlist, entry) {
-		if (strncasecmp(host, le->fqdn, strcspn(host, "/")) == 0) {
+		if (strlen(le->fqdn) == hostsz &&
+		    strncasecmp(host, le->fqdn, hostsz) == 0) {
 			shortlisted = 1;
 			break;
 		}
```