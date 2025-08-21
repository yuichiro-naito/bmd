PROG=bmdtest
CFLAGS+=-g -Wall -DLOCALBASE=\"$(LOCALBASE)\" -DTEST
LDADD=-lnv -lutil
SRCS= ../console.c ../inspect_grub.c ../vm.c ../conf.c ../control.c \
../parser.c ../conflex.c ../global.c ../server.c ../confparse.c ../inspect.c \
../tap.c ../wolmon.c ../grub_loader.c conf_test.c parser_test.c ../bmd.c \
../log.c bmdtest.c
MAN=

test: $(PROG)
	./$(PROG)

.include <bsd.prog.mk>
