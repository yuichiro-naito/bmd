LOCALBASE?= /usr/local
PLUGINDIR=$(LOCALBASE)/libexec/bmd
TARGET= libavahiplugin.so libhookcmdplugin.so
CFLAGS+=-Wall -fPIC -DLOCALBASE=\"$(LOCALBASE)\"

.PHONY: clean install installconfig installdirs

all: $(TARGET)

libavahiplugin.so: avahi.o
	$(LD) -shared -o $@ avahi.o

libhookcmdplugin.so: hookcmd.o
	$(LD) -shared -o $@ hookcmd.o

clean:
	rm -f *.o *.so

install:
	install -d $(PLUGINDIR)
	install -o root -g wheel -m 555 $(TARGET) $(PLUGINDIR)

installconfig:
installdirs:

avahi.o: avahi.c ../vars.h
hookcmd.o: hookcmd.c ../vars.h
