SUBDIR=	plugins
PROG=	bhyved
SRCS=	bhyved.c conf.c tap.c parser.c vm.c
CFLAGS+=-Wall

.include <bsd.prog.mk>
