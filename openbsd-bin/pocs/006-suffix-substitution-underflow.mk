# PoC for audit-findings/006-suffix-substitution-underflows-match-offset.md
# The suffix-anchored lhs abcdef$ is longer than the word xyz, so wordLen - leftLen underflows.
V=xyz
all:
	@echo ${V:S/abcdef$/hit/}
