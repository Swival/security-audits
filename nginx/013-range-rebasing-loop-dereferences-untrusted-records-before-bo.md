# Range rebasing loop validates record size before dereference

## Classification
- Type: trust-boundary violation
- Severity: high
- Confidence: certain

## Affected Locations
- `src/stream/ngx_stream_geo_module.c:1475`
- `src/stream/ngx_stream_geo_module.c:1476`
- `src/stream/ngx_stream_geo_module.c:1452`

## Summary
`ngx_stream_geo_include_binary_base()` walks attacker-controlled binary geo range data and dereferences `range->value` before proving a full `ngx_stream_geo_range_t` record is still within the loaded file buffer. The existing loop guard only proves the cursor is below `base + size`, not that enough bytes remain for the dereference. A truncated `.bin` file can therefore trigger an out-of-bounds read during configuration loading.

## Provenance
- Verified from reproduced behavior and source inspection in `src/stream/ngx_stream_geo_module.c`
- Reproducer confirms reachable out-of-bounds read during config parsing
- Scanner source: [Swival Security Scanner](https://swival.dev)

## Preconditions
- Attacker controls a truncated binary geo range base file
- Nginx is configured to `include` that binary geo base during config load or reload

## Proof
At `src/stream/ngx_stream_geo_module.c:1475`, the code guards the loop with a byte-level bound:
```c
while ((u_char *) range < base + size) {
```

It immediately dereferences a full struct field at `src/stream/ngx_stream_geo_module.c:1476`:
```c
    if (range->value) {
```

This requires enough remaining bytes for at least the `value` member of `ngx_stream_geo_range_t`, but the guard only guarantees that one byte remains. If the file ends inside a partial range record, the dereference reads past the trusted buffer before any per-record size validation.

The same function contains the same pattern earlier for value records at `src/stream/ngx_stream_geo_module.c:1452`, where `vv->data` is read before proving a full `ngx_stream_variable_value_t` remains in-bounds.

## Why This Is A Real Bug
The binary geo base is parsed from untrusted file contents at a trust boundary. A truncated file is sufficient to place the parser cursor on an incomplete record. Because the code reads fields from that record before validating record length, it performs undefined behavior and may crash nginx during configuration parsing or reload. This is independently reproducible from the source and does not rely on speculative control flow.

## Fix Requirement
Validate that `base + size - cursor` is at least `sizeof(ngx_stream_geo_range_t)` before any `range` field dereference, and at least `sizeof(ngx_stream_variable_value_t)` before any `vv` field dereference. Abort parsing on short records.

## Patch Rationale
The patch hardens both truncation-sensitive loops by converting the guards from cursor-only checks to full-record availability checks before each dereference. This preserves existing parsing behavior for valid files while preventing reads from incomplete attacker-controlled records.

## Residual Risk
None

## Patch
Patched in `013-range-rebasing-loop-dereferences-untrusted-records-before-bo.patch`.