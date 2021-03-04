OBJS= bhyved.o tap.o conf.o parser.o
CFLAGS+=-Wall

.PHONY: clean

bhyved:	$(OBJS)
	cc -o $@ $(OBJS)

clean:
	rm -f bhyved $(OBJS) *.core

bhyved.o: bhyved.c vars.h tap.h
conf.o: conf.c vars.h conf.h
tap.o: tap.c tap.h
parser.o: parser.c vars.h
