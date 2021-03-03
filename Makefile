OBJS= bhyved.o tap.o conf.o
CFLAGS+=-Wall

.PHONY: clean

bhyved:	$(OBJS)
	cc -o $@ $(OBJS)

clean:
	rm -f bhyved $(OBJS)

bhyved.o: bhyved.c vars.h tap.h
conf.o: conf.c vars.h conf.h
tap.o: tap.c tap.h
