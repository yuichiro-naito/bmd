CFLAGS+=	-g -Wall -DLOCALBASE=\"$(LOCALBASE)\"
LIB=		-lnv
OBJS= bmd.o ../console.o ../inspect_grub.o ../vm.o ../conf.o ../control.o \
../parser.o ../conflex.o ../global.o ../server.o ../confparse.o ../inspect.o \
../tap.o ../wolmonitor.o

TESTS= conf_test parser_test

test: $(TESTS)
.for t in $(TESTS)
	./$t
.endfor

bmd.o: ../bmd.o
	objcopy -N main ../bmd.o bmd.o

conf_test: conf_test.c $(OBJS)
	$(CC) $(CFLAGS) -o conf_test conf_test.c $(OBJS) $(LIB)

parser_test:  parser_test.c $(OBJS)
	$(CC) $(CFLAGS) -o parser_test parser_test.c $(OBJS) $(LIB)

clean:
	rm -f $(TESTS) bmd.o *.core
