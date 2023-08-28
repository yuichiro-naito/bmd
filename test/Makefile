LOCALBASE?=		/usr/local
CFLAGS+=	-g -Wall -DLOCALBASE=\"$(LOCALBASE)\"
LIB=		-lnv
TESTS= conf_test

test: $(TESTS)
.for t in $(TESTS)
	./$t
.endfor

conf_test: ../conf.o conf_test.c
	$(CC) $(CFLAGS) -o conf_test conf_test.c ../conf.o $(LIB)

clean:
	rm -f conf_test *.core
