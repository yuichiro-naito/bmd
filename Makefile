SUBDIR=	plugins
PROG=	bhyved
SRCS=	bhyved.c conf.c tap.c parser.c
CFLAGS+=-Wall

.include <bsd.prog.mk>
