dnl PoC for audit-findings/008-popdef-frees-live-macro-definition.md
dnl popdef frees foo's definition while the outer foo expansion frame still references it.
define(`foo', `A')
foo(popdef(`foo'))
