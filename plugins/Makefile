LOCALBASE?= /usr/local
PLUGINDIR=$(LOCALBASE)/libexec/bmd
TARGET= libbmdplugin_avahi.so libbmdplugin_hookcmd.so libbmdplugin_qemu.so
CFLAGS+=-Wall -fPIC -DLOCALBASE=\"$(LOCALBASE)\"

.PHONY: clean install installconfig installdirs

all: $(TARGET)

libbmdplugin_avahi.so: avahi.o
	$(LD) -shared -o $@ avahi.o

libbmdplugin_hookcmd.so: hookcmd.o
	$(LD) -shared -o $@ hookcmd.o

libbmdplugin_qemu.so: qemu.o
	$(LD) -shared -o $@ qemu.o

clean:
	rm -f *.o *.so

install:
	install -d $(PLUGINDIR)
	install -o root -g wheel -m 555 $(TARGET) $(PLUGINDIR)

installconfig:
installdirs:

avahi.o: avahi.c ../bmd_plugin.h
hookcmd.o: hookcmd.c ../bmd_plugin.h
qemu.o: qemu.c ../bmd_plugin.h
