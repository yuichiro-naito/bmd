SCRIPTS=	bmd
SCRIPTSNAME_bmd=bmd
SCRIPTSDIR=	$(LOCALBASE)/etc/rc.d

bmd:	bmd.in
	sed 's|%%LOCALBASE%%|$(LOCALBASE)|' < ${.ALLSRC} > ${.TARGET}

CLEANFILES=	${SCRIPTS}

.include <bsd.prog.mk>
