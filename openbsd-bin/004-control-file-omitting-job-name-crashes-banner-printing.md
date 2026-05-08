# Missing Job Name Crashes Banner Printing

## Classification

denial of service, medium severity, certain confidence

## Affected Locations

`usr.sbin/lpd/printer.c:563`

## Summary

A crafted LPR control file can place an `L` record before any `J` record. With leading banner printing enabled, `lpd` calls `printbanner(&job)` while `job.name` is still `NULL`. Banner rendering then passes that NULL pointer to string-handling code, crashing the printer process and causing a practical print-queue denial of service.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Leading banner printing is enabled: `!lp_sh && !lp_hl`.
- A crafted job is accepted into the print queue.
- The job control file contains an `L` record before any `J` record, or omits the `J` record entirely.

## Proof

The reproduced control-flow evidence is:

- `frontend_lpr.c:476` accepts a control-file transfer.
- `frontend_lpr.c:534` writes the supplied control-file bytes unchanged.
- `engine_lpr.c:558` validates only the control-file filename.
- `engine_lpr.c:702` publishes the control file after commit.
- `engine_lpr.c:713` starts the printer process.
- `printer.c:381` zeroes `struct job`, leaving `job.name == NULL`.
- `printer.c:424` initializes `job.name` only when a `J` record is processed.
- `printer.c:432` processes an `L` record.
- `printer.c:435` immediately calls `printbanner(&job)` when leading banners are enabled.
- `printer.c:566` passes `job->name` to `prn_puts()` for short banners.
- `printer.c:1350` calls `strlen(buf)`, so `strlen(NULL)` crashes.
- `printer.c:574` passes `job->name` to `lp_banner()` for non-short banners.
- `lp_banner.c:1132` dereferences the NULL string.
- The crash happens before `printer.c:505` unlinks the control file, so the queued malicious job can remain and crash later printer process starts.

## Why This Is A Real Bug

The control-file parser processes records in file order but assumes `job.name` has already been initialized when printing a banner. The LPR input path accepts and queues attacker-supplied control-file contents without enforcing that a `J` record precedes `L`. Therefore a remote LPR client can trigger the NULL dereference through normal queue processing. Because the control file may remain queued after the crash, the fault can persist across printer process restarts.

## Fix Requirement

`printbanner()` must not pass `NULL` as the job name to `prn_puts()` or `lp_banner()`. It must either initialize a default job name before banner printing or substitute a safe default inside banner rendering.

## Patch Rationale

The patch substitutes `" "` when `job->name` is `NULL`, matching the existing behavior used for an empty `J` record in `printjob()`. This keeps banner output semantics stable while ensuring all banner paths receive a valid string.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/lpd/printer.c b/usr.sbin/lpd/printer.c
index ca9d5c0..a1b66af 100644
--- a/usr.sbin/lpd/printer.c
+++ b/usr.sbin/lpd/printer.c
@@ -550,6 +550,7 @@ printjob(const char *cfname, int retry)
 static void
 printbanner(struct job *job)
 {
+	const char *name = job->name ? job->name : " ";
 	time_t t;
 
         time(&t);
@@ -563,7 +564,7 @@ printbanner(struct job *job)
 		}
 		prn_puts(job->literal);
 		prn_puts("  Job: ");
-		prn_puts(job->name);
+		prn_puts(name);
 		prn_puts("  Date: ");
 		prn_puts(ctime(&t));
 		prn_puts("\n");
@@ -571,13 +572,13 @@ printbanner(struct job *job)
 		prn_puts("\n\n\n");
 		lp_banner(prn->pfd, job->literal, lp->lp_pw);
 		prn_puts("\n\n");
-		lp_banner(prn->pfd, job->name, lp->lp_pw);
+		lp_banner(prn->pfd, name, lp->lp_pw);
 		if (job->class) {
 			prn_puts("\n\n\n");
 			lp_banner(prn->pfd, job->class, lp->lp_pw);
 		}
 		prn_puts("\n\n\n\n\t\t\t\t\tJob:  ");
-		prn_puts(job->name);
+		prn_puts(name);
 		prn_puts("\n\t\t\t\t\tDate: ");
 		prn_puts(ctime(&t));
 		prn_puts("\n");
```