# Non-digit port suffix accepted as valid authority

## Classification
Validation gap, medium severity, confidence: certain

## Affected Locations
- `lib/common/url.c:210`
- `lib/handler/connect.c:1068`
- `lib/handler/connect.c:1074`
- `lib/common/socketpool.c:160`
- `lib/common/socketpool.c:190`

## Summary
`h2o_url_parse_hostport` accepts an authority whose port segment starts with digits and then contains a non-digit suffix before `/`, `?`, or end of input. This causes malformed authorities such as `example.com:80x` to be treated as valid, with `_port` parsed as `80` while the invalid authority string is preserved and propagated.

## Provenance
Verified by reproduction and source inspection. Finding tracked via Swival Security Scanner: https://swival.dev

## Preconditions
URL authority contains `:` followed by a nondigit before `/`, `?`, or end of input.

## Proof
In `lib/common/url.c:210`, authority parsing reaches `h2o_url_parse_hostport` from `parse_authority_and_path`. After `:`, the parser accumulates decimal digits into the port value. Before the patch, it only treated `/`, `?`, or end-of-authority as terminators and did not reject any other non-digit byte in the port field.

With input `http://host:80x/path`:
- the parser consumes `80` into `_port`
- encounters `x`
- leaves parsing state consistent enough to return success
- preserves `authority` as `host:80x`
- stores `_port == 80`

This reachable acceptance matters in `lib/handler/connect.c:1068`, where CONNECT validation relies on `h2o_url_parse_hostport`. The call site rejects only `NULL`, `0`, and `65535`; therefore `example.com:80x` passes validation and is forwarded at `lib/handler/connect.c:1074` with `port=80`.

A second impact exists for absolute URLs parsed through `h2o_url_parse`: connection setup in `lib/common/socketpool.c:160` and `lib/common/socketpool.c:190` uses `h2o_url_get_port(url)` / `_port` for the actual network port, while the malformed `authority` string remains available for origin identity and higher-layer handling. The implementation therefore interprets `http://host:80x/path` as “connect to port 80” despite retaining an invalid authority.

## Why This Is A Real Bug
This is not a cosmetic parsing discrepancy. The code accepts syntactically invalid authority input, derives a numeric port from only the digit prefix, and continues execution as if validation succeeded. That creates inconsistent state between the retained authority string and the effective destination port, and it directly weakens CONNECT authority validation at a security-relevant boundary.

## Fix Requirement
Reject any port character that is neither a digit nor a valid authority terminator (`/`, `?`, or end of authority).

## Patch Rationale
The patch updates `h2o_url_parse_hostport` in `lib/common/url.c` so that once port parsing starts, any non-digit character other than a valid terminator causes immediate failure. This aligns parsed `_port` with the authority syntax, prevents partial numeric consumption, and closes the CONNECT validation bypass that relied on the permissive behavior.

## Residual Risk
None

## Patch
Patched in `023-non-digit-port-suffix-accepted-as-valid-authority.patch`.