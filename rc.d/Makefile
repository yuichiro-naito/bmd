LOCALBASE?=	/usr/local
CONFSDIR=	$(LOCALBASE)/etc/rc.d
CONFS=		bhyved
CONFSMODE_bhyved= 0755

bhyved:	bhyved.in
	sed 's|%%LOCALBASE%%|$(LOCALBASE)|' < bhyved.in > bhyved

clean:
	rm -f $(CONFS)

.include <bsd.prog.mk>
