# Requested extensions leak on error path

## Classification
- Type: resource lifecycle bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `crypto/x509/t_req.cc:151`

## Summary
`X509_REQ_print_ex` allocates a requested-extension stack with `X509_REQ_get_extensions(x)` and frees it only on the all-success path. If any later `BIO_printf` or `BIO_write` fails while printing those extensions, control jumps to `err` and skips the free, leaking the heap-backed extension stack and its elements.

## Provenance
- Verified finding reproduced from project source inspection and control-flow analysis
- Scanner source: https://swival.dev

## Preconditions
- CSR contains requested extensions
- A `BIO_printf` or `BIO_write` call fails after `X509_REQ_get_extensions(x)` succeeds

## Proof
- `X509_REQ_print_ex` obtains `exts` from `X509_REQ_get_extensions(x)` at `crypto/x509/t_req.cc:151`
- The function enters the requested-extensions printing block and performs multiple fallible writes, including `BIO_printf` and `BIO_write`, after allocation
- Those failures branch to `err`, but `sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free)` is only executed on the success path after the loop
- OpenSSL’s ownership contract is confirmed by `X509V3_add1_i2d`, which frees the returned extension stack with `TENSION_pop_free(exts, X509_EXTENSION_free)` at `crypto/x509/v3_utl.cc:554`
- Therefore, any write failure after allocation leaks the decoded requested-extension stack and its contained `X509_EXTENSION` objects

## Why This Is A Real Bug
The failing sink is caller-controlled through the supplied `BIO *bio`, and this function already treats write failure as a normal runtime outcome by checking return values and branching to `err`. When that happens after requested extensions are decoded, the owned heap allocation is abandoned. Repeated calls can accumulate leaked memory proportional to CSR extension content.

## Fix Requirement
Ensure the requested-extension stack is released on every exit path after allocation, including all `goto err` branches reached from the printing block.

## Patch Rationale
Route cleanup through shared exit handling by tracking `exts` across the function and freeing it before return on both success and error paths. This preserves existing behavior while restoring the documented ownership discipline for `X509_REQ_get_extensions(x)` results.

## Residual Risk
None

## Patch
- Patch file: `004-requested-extensions-leak-on-error-path.patch`
- Change: add shared cleanup for the `exts` stack in `X509_REQ_print_ex` so all post-allocation exits free `exts` with `sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free)`