MK_DEBUG_FILES?=	no
SUBDIR=		rc.d
BINDIR=		$(LOCALBASE)/sbin
MANDIR=		$(LOCALBASE)/share/man/man
DIRS=		UEFIVARDIR PLUGINDIR
UEFIVARDIR=	$(LOCALBASE)/var/cache/bmd
PLUGINDIR=	$(LOCALBASE)/libexec/bmd
PROG=		bmd
MAN=		bmd.8 bmdctl.8 bmd.conf.5
LINKS=  	${BINDIR}/bmd ${BINDIR}/bmdctl
SRCS=		bmd.c conf.c tap.c parser.c vm.c server.c control.c inspect.c \
		global.c console.c inspect_grub.c wolmon.c confparse.h \
		confparse.y conflex.l y.tab.h grub_loader.c
CFLAGS+=	-Wall -DLOCALBASE=\"$(LOCALBASE)\"
LDADD=		-lnv -lutil
LDFLAGS=	-Xlinker -dynamic-list=export.symbols
INCS=		bmd_plugin.h
INCSDIR=	$(LOCALBASE)/include
FILES=		bmd.conf.example
FILESDIR=	$(LOCALBASE)/etc
FILESMODE=	${NOBINMODE}
CLEANFILES=	y.output

WARNS?=		6

.include "Makefile.inc"
.include <bsd.prog.mk>
