MK_DEBUG_FILES?= no
LOCALBASE?= /usr/local
SUBDIR=	plugins rc.d
BINDIR=	$(LOCALBASE)/sbin
MANDIR= $(LOCALBASE)/man/man
DIRS=	VMCONFDIR
VMCONFDIR=$(LOCALBASE)/etc/bmd.d
PROG=	bmd
LINKS=  ${BINDIR}/bmd ${BINDIR}/bmdctl
SRCS=	bmd.c conf.c tap.c parser.c vm.c command.c
CFLAGS+=-Wall -DLOCALBASE=\"$(LOCALBASE)\"
LDADD=	-lnv

.include <bsd.prog.mk>
