all: libavahiplugin.so libhookcmdplugin.so

CFLAGS+=-fPIC

libavahiplugin.so: avahi.o
	$(LD) -shared -o $@ avahi.o

libhookcmdplugin.so: hookcmd.o
	$(LD) -shared -o $@ hookcmd.o

clean:
	rm -f *.o *.so

avahi.o: avahi.c ../vars.h
hookcmd.o: hookcmd.c ../vars.h
