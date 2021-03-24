SUBDIR=	plugins
PROG=	bhyved
SRCS=	bhyved.c conf.c tap.c parser.c

.include <bsd.prog.mk>
