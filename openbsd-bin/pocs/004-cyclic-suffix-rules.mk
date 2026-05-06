# PoC for audit-findings/004-cyclic-suffix-rules-cause-unbounded-implicit-source-expansio.md
# Vulnerable make repeatedly searches foo.b -> foo.c -> foo.b ... because neither source exists.
.SUFFIXES:
.SUFFIXES: .a .b .c

.b.a:
	@cp ${.IMPSRC} ${.TARGET}

.c.b:
	@cp ${.IMPSRC} ${.TARGET}

.b.c:
	@cp ${.IMPSRC} ${.TARGET}

all: foo.a
