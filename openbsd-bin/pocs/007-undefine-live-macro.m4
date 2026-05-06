dnl PoC for audit-findings/007-undefine-frees-live-macro-definition.md
dnl undefine frees foo's definition while the outer foo expansion frame still references it.
define(`foo', `A')
foo(undefine(`foo'))
