PROG=bmdtest
CFLAGS+=-g -Wall -DLOCALBASE=\"$(LOCALBASE)\"
LDADD=-lnv -lutil
SRCS= ../console.c ../inspect_grub.c ../vm.c ../conf.c ../control.c \
../parser.c ../conflex.c ../global.c ../server.c ../confparse.c ../inspect.c \
../tap.c ../wolmon.c ../grub_loader.c conf_test.c parser_test.c main.c
OBJS=bmd-test.pieo
MAN=

test: $(PROG)
	./$(PROG)

bmd-test.pieo: ../bmd.c
	$(CC) -c -o $@ $(CFLAGS) -DTEST ../bmd.c

.include <bsd.prog.mk>
