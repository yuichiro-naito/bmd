all: libavahiplugin.so

CFLAGS+=-fPIC

libavahiplugin.so: avahi.o
	$(LD) -shared -o $@ avahi.o

clean:
	rm -f *.o *.so
