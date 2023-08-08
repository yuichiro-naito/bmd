LOCALBASE?=	/usr/local
SCRIPTS=	bmd
SCRIPTSNAME_bmd=bmd
SCRIPTSDIR=	$(LOCALBASE)/etc/rc.d

bmd:	bmd.in
	sed 's|%%LOCALBASE%%|$(LOCALBASE)|' < bmd.in > bmd

clean:
	rm -f $(SCRIPTS)

.include <bsd.prog.mk>
