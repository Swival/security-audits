# FTP delete command injection in `del!FTP`

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `std/net/curl.d:574`

## Summary
`del!FTP` constructs an FTP `DELE` command by concatenating the untrusted URL path directly into `conn.addCommand("DELE " ~ t[1])`. `FTP.addCommand` forwards that string to libcurl as a raw `postquote` control-channel command. Because no validation rejects embedded CR or LF, attacker-controlled input can terminate the intended `DELE` and inject additional FTP commands.

## Provenance
- Verified finding reproduced and patched from local analysis and runtime confirmation
- Scanner source: https://swival.dev

## Preconditions
- Caller invokes FTP `del` with attacker-controlled URL path
- The supplied D string contains literal CR and/or LF characters in the FTP path segment

## Proof
- In `std/net/curl.d:574`, `del!FTP` parses the FTP URL, stores the host portion in `conn.url`, and appends the remaining path as `conn.addCommand("DELE " ~ t[1])`
- `FTP.addCommand` stores the provided value as a raw FTP `postquote` command, with no escaping or newline filtering before libcurl transmits it
- Reproduction confirmed that embedding literal `\r\nNOOP` in the attacker-controlled path causes two control-channel commands to be sent: `DELE file` and `NOOP`
- This demonstrates that the path is interpreted as FTP command text, not as a safely delimited delete operand

## Why This Is A Real Bug
The vulnerable behavior is directly reachable in normal API usage: `del!FTP` accepts a caller-provided URL string and emits a raw FTP control command containing untrusted bytes. Embedded CR/LF changes protocol framing on the control channel, allowing arbitrary command injection within the authenticated FTP session. This is a concrete integrity-impacting vulnerability, not a hypothetical parser concern.

## Fix Requirement
Reject unsafe bytes in the FTP delete path before constructing the `DELE` command, specifically CR and LF at minimum, so one caller input cannot produce multiple FTP control-channel commands.

## Patch Rationale
The patch enforces input validation at the sink used by `del!FTP`, preventing protocol-framing characters from reaching `CURLOPT_POSTQUOTE`. This preserves existing behavior for valid paths while blocking the demonstrated command-injection primitive with minimal surface-area change.

## Residual Risk
None

## Patch
- Patch file: `003-ftp-delete-command-injection-via-unsanitized-path.patch`
- Patched behavior: FTP delete paths containing CR or LF are rejected before `addCommand` is called
- Security effect: user-controlled input can no longer split a single `DELE` operation into multiple FTP commands