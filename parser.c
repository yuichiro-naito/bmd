#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <ctype.h>

#include "conf.h"
#include "parser.h"

static int
get_token(FILE *fp, char **token)
{
	int c, f;
	FILE *t;
	char *buf;
	size_t len;

	if (feof(fp))
		return 1;

	t = open_memstream(&buf, &len);

	f = 0;
	while ((c = fgetc(fp)) != EOF) {
		if (c == '#') {
			while (fgetc(fp) != '\n');
		} else if (c == '=' || c == '\n') {
			if (f == 1) {
				f = 0;
				ungetc(c, fp);
				break;
			} else {
				fputc(c, t);
				break;
			}
		} else if (c == ',') {
			if (f == 1) {
				f = 0;
				break;
			}
		} else if (c == '\\') {
			c = fgetc(fp);
			switch (c) {
			case 't':
				fputc('\t', t);
				break;
			case 'n':
				fputc('\n', t);
				break;
			case 'r':
				fputc('\r', t);
				break;
			case '\r':
			case '\n':
				continue;
			default:
				fputc(c, t);
			}
		} else if (isspace(c)) {
			if (f == 0)
				continue;
			else {
				f = 0;
				break;
			}
		} else {
			f = 1;
			fputc(c, t);
		}
	}

	if (ftell(t) == 0) {
		fclose(t);
		return 1;
	}

	fflush(t);
	*token = strdup(buf);
	fclose(t);

	return 0;
}

typedef int (*pfunc)(struct vm_conf *conf, char *val);

static int
parse_name(struct vm_conf *conf, char *val)
{
	set_name(conf, val);
	return 0;
}

static int
parse_ncpu(struct vm_conf *conf, char *val)
{
	long n;
	char *p;
	n = strtol(val, &p, 10);
	if (*p != '\0')
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
parse_boot(struct vm_conf *conf, char *val)
{
	enum BOOT b;

	if (strcasecmp(val, "yes") == 0 ||
	    strcasecmp(val, "true") == 0)
		b = YES;
	else if (strcasecmp(val, "delay") == 0 ||
		 strcasecmp(val, "delayed") == 0)
		b = DELAYED;
	else if (strcasecmp(val, "oneshot") == 0)
		b = ONESHOT;
	else if (strcasecmp(val, "install") == 0)
		b = INSTALL;
	else
		b = NO;

	set_boot(conf, b);
	return 0;
}

static int
parse_comport(struct vm_conf *conf, char *val)
{
	set_comport(conf, val);
	return 0;
}

static pfunc
get_parser(char *name)
{
	if (strcasecmp(name, "name") == 0)
		return &parse_name;
	if (strcasecmp(name, "ncpu") == 0)
		return &parse_ncpu;
	if (strcasecmp(name, "memory") == 0)
		return &parse_memory;
	if (strcasecmp(name, "disk") == 0)
		return &parse_disk;
	if (strcasecmp(name, "iso") == 0)
		return &parse_iso;
	if (strcasecmp(name, "network") == 0)
		return &parse_net;
	if (strcasecmp(name, "loadcmd") == 0)
		return &parse_loadcmd;
	if (strcasecmp(name, "boot") == 0)
		return &parse_boot;
	if (strcasecmp(name, "comport") == 0)
		return &parse_comport;


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
			fprintf(stderr, "value not found for %s\n", key);
			free(key);
			goto bad;
		}

		parser = get_parser(key);
		if (parser == NULL) {
			fprintf(stderr, "unknown key %s\n", key);
			free(key);
			goto bad;
		}
		while (1) {
			if (get_token(fp, &val) == 1)
				break;
			if (val[0] == '\n') {
				free(val);
				break;
			}

			if ((*parser)(conf, val) < 0) {
				fprintf(stderr, "invalid value %s\n", val);
				free(val);
				free(key);
				goto bad;
			}
			free(val);
		}
		free(key);
	}

	return 0;
bad:
	return -1;
}

struct vm_conf *
parse_file(char *name)
{
	int ret;
	struct vm_conf *c;
	char *bname;

	FILE *fp = fopen(name, "r");
	if (fp == NULL)
		return NULL;

	bname = strdup(name);
	c = create_vm_conf(basename(bname));
	free(bname);
	if (c == NULL)
		return NULL;

	ret = parse(c, fp);

	fclose(fp);
	if (ret < 0) {
		free_vm_conf(c);
		return NULL;
	}
	return c;
}
