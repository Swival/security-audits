# Malicious CDDB Reply Grows Track Title Without Bound

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.bin/cdio/cddb.c:367`

## Summary

A malicious CDDB server can send repeated `TTITLE` records for the same track before the terminating `.` line. The client accepts each duplicate record and appends it to the existing title, causing unbounded heap growth until memory is exhausted or the process is killed.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The user queries an attacker-controlled CDDB host.

## Proof

The CDDB response parser reads lines until `.` or EOF. For each line beginning with `TTITLE`, it parses the track index with:

`strtonum(line, 0, n - 1, &errstr)`

For a disc with `n >= 1`, `TTITLE0=...` is accepted. The parser then calls:

`safe_copy(&result[k], end)`

There is no duplicate rejection and no cumulative length cap. `MAXSIZE` limits only each individual escaped fragment. After the first `strdup`, subsequent duplicate titles are appended with:

`asprintf(&n, "%s%s", *p, copy_buffer)`

An attacker-controlled CDDB server can therefore stream repeated `TTITLE0=...` lines indefinitely before sending `.` or by never terminating the record, forcing arbitrary client-side memory growth.

## Why This Is A Real Bug

The attacker controls the CDDB response stream. The parser intentionally accepts multiple matching `TTITLE` lines for the same valid track index and retains the cumulative appended title. Because the read loop is bounded only by `.` or EOF, and the retained allocation grows on every duplicate line, the client can be driven into memory exhaustion through network input alone.

## Fix Requirement

Reject duplicate `TTITLE` records for the same track, or otherwise enforce a strict cumulative per-title length limit before appending.

## Patch Rationale

The patch rejects duplicate `TTITLE` records by checking whether `result[k]` is already populated before calling `safe_copy`. This preserves the first title for each track and prevents repeated records from increasing retained memory.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/cdio/cddb.c b/usr.bin/cdio/cddb.c
index babce4a..7c54832 100644
--- a/usr.bin/cdio/cddb.c
+++ b/usr.bin/cdio/cddb.c
@@ -365,6 +365,8 @@ cddb(const char *host_port, int n, struct cd_toc_entry *e, char *arg)
 		k = strtonum(line, 0, n - 1, &errstr);
 		if (errstr != NULL)
 			continue;
+		if (result[k] != NULL)
+			continue;
 		safe_copy(&result[k], end);
 	}
 	fprintf(cout, "QUIT\r\n");
```