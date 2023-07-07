MK_DEBUG_FILES?= no
LOCALBASE?= /usr/local
SUBDIR=	plugins rc.d
BINDIR=	$(LOCALBASE)/sbin
MANDIR= $(LOCALBASE)/man/man
DIRS=	VMCONFDIR UEFIVARDIR
VMCONFDIR=$(LOCALBASE)/etc/bmd.d
UEFIVARDIR=$(LOCALBASE)/var/cache/bmd
PROG=	bmd
LINKS=  ${BINDIR}/bmd ${BINDIR}/bmdctl
SRCS=	bmd.c conf.c tap.c parser.c vm.c server.c control.c inspect.c \
	console.c inspect_grub.c confparse.h confparse.y conflex.l y.tab.h
CFLAGS+=-Wall -DLOCALBASE=\"$(LOCALBASE)\"
LDADD=	-lnv

CLEANFILES= y.output

.include <bsd.prog.mk>
