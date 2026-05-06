# PoC for audit-findings/005-empty-global-substitution-never-advances.md
# Empty unanchored :S with g never advances; nonempty RHS makes memory grow.
V=trigger
all:
	@echo ${V:S//X/g}
