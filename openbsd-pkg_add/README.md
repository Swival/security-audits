# OpenBSD pkg_add Audit Findings

Security audit of OpenBSD's `pkg_add`, the package installation tool, along with the supporting Perl modules under `OpenBSD/` that handle repositories, ustar archive extraction, and the on-disk package database. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 7** -- High: 5, Medium: 1, Low: 1

## Findings

### Repository handlers

| # | Finding | Severity |
|---|---------|----------|
| [001](001-repository-url-is-executed-through-the-shell.md) | Repository URL is executed through the shell | High |
| [002](002-repository-eof-hangs-header-parser.md) | Repository EOF hangs HTTP reader | Low |
| [006](006-scp-repository-host-injects-ssh-options.md) | scp repository host injects ssh options | High |

### Archive extraction

| # | Finding | Severity |
|---|---------|----------|
| [003](003-archive-path-escapes-destination-tree.md) | Archive path escapes destination tree | High |
| [004](004-symlink-entry-redirects-later-file-extraction.md) | Symlink entry redirects later file extraction | High |
| [007](007-archive-mode-validation-uses-wrong-object.md) | Archive mode validation uses wrong object | High |

### Package database

| # | Finding | Severity |
|---|---------|----------|
| [005](005-package-database-repair-follows-metadata-symlinks.md) | Package database repair follows metadata symlinks | Medium |
