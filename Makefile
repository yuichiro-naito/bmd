LOCALBASE?= /usr/local
SUBDIR=	plugins rc.d
BINDIR=	$(LOCALBASE)/sbin
MANDIR= $(LOCALBASE)/man/man
DIRS=	VMCONFDIR
VMCONFDIR=$(LOCALBASE)/etc/bhyved.d
PROG=	bhyved
SRCS=	bhyved.c conf.c tap.c parser.c vm.c
CFLAGS+=-Wall -DLOCALBASE=\"$(LOCALBASE)\"

.include <bsd.prog.mk>
