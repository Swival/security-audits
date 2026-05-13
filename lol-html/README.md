# lol-html Audit Findings

Security audit of [lol-html](https://github.com/cloudflare/lol-html), Cloudflare's low-output-latency streaming HTML rewriter. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 2** -- Medium: 2

## Findings

### Streaming parser resource limits

| # | Finding | Severity |
|---|---------|----------|
| [001](001-unbounded-namespace-stack-growth-on-nested-foreign-tags.md) | Unbounded namespace stack growth on nested foreign tags | Medium |
| [002](002-nth-of-type-counters-bypass-memory-limiter.md) | nth-of-type counters bypass the memory limiter | Medium |
