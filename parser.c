#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "vars.h"
#include "conf.h"
#include "parser.h"
#include "log.h"

static int
get_token(FILE *fp, char **token)
{
	int c;
	enum PSTATE {
		BEGIN,
		TOKEN,
		QUOTE
	} f;
	FILE *t;
	char *buf;
	size_t len;

	if (feof(fp))
		return 1;

	t = open_memstream(&buf, &len);
	flockfile(t);

#define FPUTC  fputc_unlocked

	f = BEGIN;
	while ((c = fgetc(fp)) != EOF) {
		switch (c) {
		case '#':
			switch (f) {
			case TOKEN:
			case QUOTE:
				FPUTC(c, t);
				continue;
			default:
				flockfile(fp);
				while ((getc_unlocked(fp)) != '\n');
				funlockfile(fp);
				FPUTC('\n', t);
				goto loop_end;
			}
		case '"':
			switch (f) {
			case QUOTE:
				f = BEGIN;
				goto loop_end;
			case TOKEN:
				FPUTC(c, t);
				continue;
			default:
				f = QUOTE;
			}
			break;
		case '=':
		case '\n':
			switch (f) {
			case QUOTE:
				FPUTC(c, t);
				continue;
			case TOKEN:
				ungetc(c, fp);
				break;
			default:
				FPUTC(c, t);
			}
			goto loop_end;
		case '\\':
			c = fgetc(fp);
			switch (c) {
			case 'f':
				FPUTC('\f', t);
				break;
			case 't':
				FPUTC('\t', t);
				break;
			case 'n':
				FPUTC('\n', t);
				break;
			case 'r':
				FPUTC('\r', t);
				break;
			case 'v':
				FPUTC('\v', t);
				break;
			case '\r':
			case '\n':
				if (f == QUOTE)
					FPUTC(c, t);
				continue;
			default:
				FPUTC(c, t);
			}
			break;
		case ' ':
		case '\t':
		case '\r':
		case '\v':
		case '\f':
			switch(f) {
			case QUOTE:
				FPUTC(c, t);
				continue;
			case TOKEN:
				goto loop_end;
			default:
				break;
			}
			break;
		default:
			if (f == BEGIN)
				f = TOKEN;
			FPUTC(c, t);
		}
	}

loop_end:
	funlockfile(t);

	if (ftell(t) == 0) {
		fclose(t);
		free(buf);
		return 1;
	}

	fclose(t);
	*token = buf;

	return 0;
}

typedef int (*pfunc)(struct vm_conf *conf, char *val);

static int
parse_int(int *val, char *value)
{
	long n;
	char *p;

	n = strtol(value, &p, 10);
	if (*p != '\0') {
		return -1;
	}
	*val = n;
	return 0;
}

static int
parse_name(struct vm_conf *conf, char *val)
{
	set_name(conf, val);
	return 0;
}

static int
parse_ncpu(struct vm_conf *conf, char *val)
{
	int n;

	if (parse_int(&n, val) < 0)
		return -1;

	set_ncpu(conf, n);
	return 0;
}

static int
parse_memory(struct vm_conf *conf, char *val)
{
	long n;
	char *p;

	n = strtol(val, &p, 10);
	switch (*p) {
	case '\0':
		break;
	case 'T':
	case 't':
	case 'G':
	case 'g':
	case 'M':
	case 'm':
	case 'K':
	case 'k':
		if (p[1] != '\0') return -1;
		break;
	default:
		return -1;
	}

	set_memory_size(conf, val);
	return 0;
}

static int
parse_disk(struct vm_conf *conf, char *val)
{
	char *c;

	c = strchr(val, ':');
	if (c == NULL)
		return add_disk_conf(conf, "virtio-blk", val);

	*c = '\0';
	if (strcmp(val, "ahci-hd") != 0 &&
	    strcmp(val, "virtio-blk") != 0) {
		*c = ':';
		return -1;
	}

	return add_disk_conf(conf, val, c+1);
}

static int
parse_iso(struct vm_conf *conf, char *val)
{
	char *c;

	c = strchr(val, ':');
	if (c == NULL)
		return add_iso_conf(conf, "ahci-cd", val);

	*c = '\0';
	if (strcmp(val, "ahci-cd") != 0) {
		*c = ':';
		return -1;
	}

	return add_iso_conf(conf, val, c+1);
}

static int
parse_net(struct vm_conf *conf, char *val)
{
	char *c;

	c = strchr(val, ':');
	if (c == NULL)
		return add_net_conf(conf, "virtio-net", val);

	*c = '\0';
	if (strcmp(val, "e1000") != 0 &&
	    strcmp(val, "virtio-net") != 0) {
		*c = ':';
		return -1;
	}

	return add_net_conf(conf, val, c+1);
}

static int
parse_loadcmd(struct vm_conf *conf, char *val)
{
	set_loadcmd(conf, val);
	return 0;
}

static int
parse_installcmd(struct vm_conf *conf, char *val)
{
	set_installcmd(conf, val);
	return 0;
}

static int
parse_hookcmd(struct vm_conf *conf, char *val)
{
	set_hookcmd(conf, val);
	return 0;
}

static int
parse_err_logfile(struct vm_conf *conf, char *val)
{
	set_err_logfile(conf, val);
	return 0;
}

static int
parse_loader(struct vm_conf *conf, char *val)
{
	if (strcasecmp(val, "uefi") != 0 &&
	    strcasecmp(val, "bhyveload") != 0 &&
	    strcasecmp(val, "grub") != 0)
		return -1;

	set_loader(conf, val);
	return 0;
}

static int
parse_loader_timeout(struct vm_conf *conf, char *val)
{
	int timeout;

	if (parse_int(&timeout, val) < 0)
		return -1;

	return set_loader_timeout(conf, timeout);
}

static int
parse_boot(struct vm_conf *conf, char *val)
{
	enum BOOT b;

	if (strcasecmp(val, "yes") == 0 ||
	    strcasecmp(val, "true") == 0)
		b = YES;
	else if (strcasecmp(val, "oneshot") == 0)
		b = ONESHOT;
	else if (strcasecmp(val, "install") == 0)
		b = INSTALL;
	else if (strcasecmp(val, "always") == 0)
		b = ALWAYS;
	else if (strcasecmp(val, "reboot") == 0)
		b = REBOOT;
	else
		b = NO;

	set_boot(conf, b);
	return 0;
}

static int
parse_boot_delay(struct vm_conf *conf, char *val)
{
	int delay;

	if (parse_int(&delay, val) < 0)
		return -1;

	return set_boot_delay(conf, delay);
}

static int
parse_comport(struct vm_conf *conf, char *val)
{
	set_comport(conf, val);
	return 0;
}

static bool
parse_boolean(const char *value)
{
	if (strcasecmp(value, "yes") == 0 ||
	    strcasecmp(value, "true") == 0)
		return true;
	return false;
}

static int
parse_graphics(struct vm_conf *conf, char *val)
{
	return set_fbuf_enable(conf->fbuf, parse_boolean(val));
}

static int
parse_graphics_port(struct vm_conf *conf, char *val)
{
	int port;

	if (parse_int(&port, val) < 0)
		return -1;

	return set_fbuf_port(conf->fbuf, port);
}

static int
parse_graphics_listen(struct vm_conf *conf, char *val)
{
	return set_fbuf_ipaddr(conf->fbuf, val);
}

static int
parse_graphics_res(struct vm_conf *conf, char *val)
{
	char *p;
	int width, height;

	p = strchr(val, 'x');
	if (p == NULL) return -1;

	*p = '\0';

	if (parse_int(&width, val) < 0 ||
	    parse_int(&height, p+1) < 0)
		return -1;

	return set_fbuf_res(conf->fbuf, width, height);
}

static int
parse_graphics_vga(struct vm_conf *conf, char *val)
{
	return set_fbuf_vgaconf(conf->fbuf, val);
}

static int
parse_graphics_wait(struct vm_conf *conf, char *val)
{
	return set_fbuf_wait(conf->fbuf, parse_boolean(val));
}

static int
parse_graphics_password(struct vm_conf *conf, char *val)
{
	return set_fbuf_password(conf->fbuf, val);
}

static int
parse_xhci_mouse(struct vm_conf *conf, char *val)
{
	return set_mouse(conf, parse_boolean(val));
}

static pfunc
get_parser(char *name)
{
	switch (name[0]) {
	case 'b':
		if (strcasecmp(name, "boot") == 0)
			return &parse_boot;
		else if (strcasecmp(name, "boot_delay") == 0)
			return &parse_boot_delay;
		break;
	case 'c':
		if (strcasecmp(name, "comport") == 0)
			return &parse_comport;
		break;
	case 'd':
		if (strcasecmp(name, "disk") == 0)
			return &parse_disk;
		break;
	case 'e':
		if (strcasecmp(name, "err_logfile") == 0)
			return &parse_err_logfile;
		break;
	case 'g':
		if (strcasecmp(name, "graphics") == 0)
			return &parse_graphics;
		else if (strcasecmp(name, "graphics_port") == 0)
			return &parse_graphics_port;
		else if (strcasecmp(name, "graphics_listen") == 0)
			return &parse_graphics_listen;
		else if (strcasecmp(name, "graphics_res") == 0)
			return &parse_graphics_res;
		else if (strcasecmp(name, "graphics_vga") == 0)
			return &parse_graphics_vga;
		else if (strcasecmp(name, "graphics_wait") == 0)
			return &parse_graphics_wait;
		else if (strcasecmp(name, "graphics_password") == 0)
			return &parse_graphics_password;
		break;
	case 'h':
		if (strcasecmp(name, "hookcmd") == 0)
			return &parse_hookcmd;
		break;
	case 'i':
		if (strcasecmp(name, "installcmd") == 0)
			return &parse_installcmd;
		else if (strcasecmp(name, "iso") == 0)
			return &parse_iso;
		break;
	case 'l':
		if (strcasecmp(name, "loader") == 0)
			return &parse_loader;
		else if (strcasecmp(name, "loader_timeout") == 0)
			return &parse_loader_timeout;
		else if (strcasecmp(name, "loadcmd") == 0)
			return &parse_loadcmd;
		break;
	case 'n':
		if (strcasecmp(name, "name") == 0)
			return &parse_name;
		else if (strcasecmp(name, "ncpu") == 0)
			return &parse_ncpu;
		else if (strcasecmp(name, "network") == 0)
			return &parse_net;
		break;
	case 'm':
		if (strcasecmp(name, "memory") == 0)
			return &parse_memory;
		break;
	case 'x':
		if (strcasecmp(name, "xhci_mouse") == 0)
			return &parse_xhci_mouse;
		break;
	}
	return NULL;
}

static int
parse(struct vm_conf *conf, FILE *fp)
{
	char *key;
	char *val;
	pfunc parser;

	while (1) {
		if (get_token(fp, &key) == 1) break;
		if (key[0] == '\n') {
			free(key);
			continue;
		}

		if (get_token(fp, &val) == 1) {
			free(key);
			break;
		}
		if (val[0] != '=') {
			ERR("value not found for %s\n", key);
			goto bad;
		}

		parser = get_parser(key);
		if (parser == NULL) {
			ERR("unknown key %s\n", key);
			goto bad;
		}
		free(key);
		key = NULL;
		free(val);
		while (1) {
			if (get_token(fp, &val) == 1)
				break;
			if (val[0] == '\n') {
				free(val);
				break;
			}

			if ((*parser)(conf, val) < 0) {
				ERR("invalid value %s\n", val);
				goto bad;
			}
			free(val);
		}
	}

	return 0;
bad:
	free(key);
	free(val);
	return -1;
}

int
check_conf(struct vm_conf *conf)
{
	char *name = conf->name;

	if (name == NULL) {
		ERR("%s\n", "vm name is required");
		return -1;
	}

	if (conf->ncpu == NULL) {
		ERR("ncpu is required for vm %s\n", name);
		return -1;
	}

	if (conf->memory == NULL) {
		ERR("memory is required for vm %s\n", name);
		return -1;
	}

	if (conf->loader == NULL) {
		ERR("loader is required for vm %s\n", name);
		return -1;
	}

	return 0;
}

struct vm_conf *
parse_file(int fd, char *name)
{
	int ret;
	struct vm_conf *c;

	FILE *fp = fdopen(fd, "r");
	if (fp == NULL)
		return NULL;

	c = create_vm_conf(name);
	if (c == NULL) {
		fclose(fp);
		return NULL;
	}

	ret = parse(c, fp);

	fclose(fp);
	if (ret < 0 || check_conf(c) < 0) {
		free_vm_conf(c);
		return NULL;
	}
	return c;
}
