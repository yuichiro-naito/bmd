LOCALBASE?=	/usr/local
CONFSDIR=	$(LOCALBASE)/etc/rc.d
CONFS=		bmd
CONFSMODE_bmd= 0755

bmd:	bmd.in
	sed 's|%%LOCALBASE%%|$(LOCALBASE)|' < bmd.in > bmd

clean:
	rm -f $(CONFS)

.include <bsd.prog.mk>
