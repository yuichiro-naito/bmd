#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_bridgevar.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "log.h"
#include "vm.h"

static int
getifflags(int s, const char *ifname)
{
	struct ifreq my_ifr;

	memset(&my_ifr, 0, sizeof(my_ifr));
	(void)strlcpy(my_ifr.ifr_name, ifname, sizeof(my_ifr.ifr_name));
	if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&my_ifr) < 0) {
		return -1;
	}

	return ((my_ifr.ifr_flags & 0xffff) | (my_ifr.ifr_flagshigh << 16));
}

static int
setifflags(int s, const char *name, int value)
{
	struct ifreq my_ifr;
	int flags;

	flags = getifflags(s, name);
	if (value < 0) {
		value = -value;
		flags &= ~value;
	} else
		flags |= value;
	memset(&my_ifr, 0, sizeof(my_ifr));
	(void)strlcpy(my_ifr.ifr_name, name, sizeof(my_ifr.ifr_name));
	my_ifr.ifr_flags = flags & 0xffff;
	my_ifr.ifr_flagshigh = flags >> 16;
	return (ioctl(s, SIOCSIFFLAGS, (caddr_t)&my_ifr));
}

int
add_to_bridge(int s, const char *bridge, const char *tap)
{
	struct ifdrv ifd;
	struct ifbreq req;

	if (tap == NULL)
		return 0;

	memset(&ifd, 0, sizeof(ifd));
	memset(&req, 0, sizeof(req));

	strlcpy(req.ifbr_ifsname, tap, sizeof(req.ifbr_ifsname));

	strlcpy(ifd.ifd_name, bridge, sizeof(ifd.ifd_name));
	ifd.ifd_cmd = BRDGADD;
	ifd.ifd_len = sizeof(req);
	ifd.ifd_data = &req;

	return (ioctl(s, SIOCSDRVSPEC, &ifd));
}

int
activate_tap(int s, const char *name)
{
	if (name == NULL)
		return 0;
	return setifflags(s, name, IFF_UP);
}

int
create_tap(int s, char **name)
{
	struct ifreq ifr;

	if (name == NULL)
		return -1;

	memset(&ifr, 0, sizeof(struct ifreq));
	strcpy(ifr.ifr_name, "tap");
	if (ioctl(s, SIOCIFCREATE2, &ifr) < 0) {
		switch (errno) {
		case EEXIST:
			ERR("interface %s already exists\n", ifr.ifr_name);
		default:
			ERR("%s\n", "SIOCIFCREATE2");
		}
		return -1;
	}

	*name = strdup(ifr.ifr_name);
	return 0;
}

int
destroy_tap(int s, const char *name)
{
	struct ifreq ifr;

	if (name == NULL)
		return 0;

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

	return (ioctl(s, SIOCIFDESTROY, &ifr));
}

int
set_tap_description(int s, const char *tap, char *desc)
{
	struct ifreq ifr;

	if (tap == NULL)
		return 0;

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, tap, sizeof(ifr.ifr_name));

	ifr.ifr_buffer.length = strlen(desc) + 1;
	if (ifr.ifr_buffer.length == 1) {
		ifr.ifr_buffer.buffer = NULL;
		ifr.ifr_buffer.length = 0;
	} else
		ifr.ifr_buffer.buffer = desc;

	return (ioctl(s, SIOCSIFDESCR, (caddr_t)&ifr));
}
