#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "conf.h"
#include "log.h"
#include "parser.h"
#include "bmd.h"

#define FPUTC fputc_unlocked

static int
arithmetic_calc(FILE *fp, struct vm_conf *conf, int *ret) {
	int c, s = 0;
	FILE *t;
	char *buf;
	size_t len;

	t = open_memstream(&buf, &len);
	flockfile(t);

	while ((c = fgetc(fp)) != EOF) {
		FPUTC(c, t);
		switch (c) {
		case '(':
			++s;
			break;
		case ')':
			if (--s == 0)
				goto loop_end;
		}
	}
loop_end:
	funlockfile(t);
	fclose(t);
	if (c == ')') {
		t = fmemopen(buf, len, "r");
		c = reverse_polish_notation(t, conf, ret);
		fclose(t);
	} else
		c = -2;
	free(buf);
	return c;
}

int
parse_variable(FILE *fp, struct vm_conf *conf, char **value, long *num)
{
	char c, *key, *val, *p;
	long vstart, n;
	size_t buflen;

	vstart = ftell(fp);
	if (fgetc(fp) != '{')
		goto err;
	flockfile(fp);
	while ((c = getc_unlocked(fp)) != '}')
		if (!(isalnum(c) || c == '_'))
			break;
	funlockfile(fp);
	if (c != '}')
		goto err;
	buflen = ftell(fp) - vstart - 1;
	/* ignore very long variable name */
	if (buflen > 10*1024 ||
	    (key = malloc(buflen)) == NULL)
		goto err;
	fseek(fp, vstart + 1, SEEK_SET);
	if (fread(key, 1, buflen, fp) < 0) {
		free(key);
		goto err;
	}
	key[buflen - 1] = '\0';
	if ((val = get_var(conf, key)) == NULL) {
		ERR("%s: ${%s} is undefined", conf->name, key);
		free(key);
		return 0;
	}

	if (value)
		*value = val;

	if (num) {
		n = strtol(val, &p, 10);
		if (*p != '\0')
			ERR("%s: ${%s} is not a number",
			    conf->name, key);
		else
			*num = n;
	}

	free(key);
	return strlen(val);

err:
	fseek(fp, vstart, SEEK_SET);
	return -1;
}


static int
get_token(FILE *fp, char **token, struct vm_conf *conf)
{
	int c, num, rc;
	enum PSTATE { BEGIN, TOKEN, QUOTE } f;
	FILE *t;
	char *buf, *val;
	size_t len;
	long vstart;

	if (feof(fp))
		return 1;

	t = open_memstream(&buf, &len);
	flockfile(t);

	f = BEGIN;
	while ((c = fgetc(fp)) != EOF) {
		switch (c) {
		case '$':
			if (conf == NULL) {
				if (f == BEGIN)
					f = TOKEN;
				FPUTC(c, t);
				continue;
			}
			vstart = ftell(fp);
			if (fgetc(fp) == '(' && fgetc(fp) == '(') {
				fseek(fp, vstart, SEEK_SET);
				rc = arithmetic_calc(fp, conf, &num);
				if (rc == -2) {
					fwrite("$((", 1, 3, t);
					fseek(fp, vstart + 2, SEEK_SET);
					continue;
				}
				if (rc < 0 || fprintf(t, "%d", num) < 0)
					continue;
				goto loop_end;
			}
			if (f == BEGIN)
				f = TOKEN;
			fseek(fp, vstart, SEEK_SET);
			rc = parse_variable(fp, conf, &val, NULL);
			if (rc < 0)
				FPUTC('$', t);
			else if (rc > 0)
				fwrite_unlocked(val, 1, rc, t);
			continue;
		case '#':
			switch (f) {
			case TOKEN:
			case QUOTE:
				FPUTC(c, t);
				continue;
			default:
				flockfile(fp);
				while ((c = getc_unlocked(fp)) != '\n')
					if (c == EOF)
						break;
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
			switch (f) {
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

static int
parse_int(int *val, char *value)
{
	long n;
	char *p;

	n = strtol(value, &p, 10);
	if (*p != '\0')
		return -1;
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
	char *p;

	strtol(val, &p, 10);
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
		if (p[1] != '\0')
			return -1;
		break;
	default:
		return -1;
	}

	set_memory_size(conf, val);
	return 0;
}

static int
parse_passthru(struct vm_conf *conf, char *val)
{
	char *p;
	for (p = val; *p != '\0'; p++)
		if (*p != '/' && (*p < '0' || *p > '9'))
			return -1;

	return add_passthru_conf(conf, val);
}

static int
parse_disk(struct vm_conf *conf, char *val)
{
	size_t n;
	const char **p, *types[] = { "ahci-hd:", "virtio-blk:", "nvme:" };

	ARRAY_FOREACH (p, types) {
		n = strlen(*p);
		if (strncmp(val, *p, n) == 0) {
			val[n - 1] = '\0';
			return add_disk_conf(conf, val, &val[n]);
		}
	}

	return add_disk_conf(conf, "virtio-blk", val);
}

static int
parse_iso(struct vm_conf *conf, char *val)
{
	size_t n;
	const char **p, *types[] = { "ahci-cd:" };

	ARRAY_FOREACH (p, types) {
		n = strlen(*p);
		if (strncmp(val, *p, n) == 0) {
			val[n - 1] = '\0';
			return add_iso_conf(conf, val, &val[n]);
		}
	}

	return add_iso_conf(conf, "ahci-cd", val);
}

static int
parse_net(struct vm_conf *conf, char *val)
{
	size_t n;
	const char **p, *types[] = { "virtio-net:", "e1000:" };

	ARRAY_FOREACH (p, types) {
		n = strlen(*p);
		if (strncmp(val, *p, n) == 0) {
			val[n - 1] = '\0';
			return add_net_conf(conf, val, &val[n]);
		}
	}

	return add_net_conf(conf, "virtio-net", val);
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
parse_err_logfile(struct vm_conf *conf, char *val)
{
	set_err_logfile(conf, val);
	return 0;
}

static int
parse_loader(struct vm_conf *conf, char *val)
{
	const char **p, *values[] = { "uefi", "csm", "bhyveload", "grub" };

	ARRAY_FOREACH (p, values)
		if (strcasecmp(val, *p) == 0)
			return set_loader(conf, val);
	return -1;
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
parse_stop_timeout(struct vm_conf *conf, char *val)
{
	int timeout;

	if (parse_int(&timeout, val) < 0)
		return -1;

	return set_stop_timeout(conf, timeout);
}

static int
parse_grub_run_partition(struct vm_conf *conf, char *val)
{
	return set_grub_run_partition(conf, val);
}

static int
parse_debug_port(struct vm_conf *conf, char *val)
{
	return set_debug_port(conf, val);
}

static int
parse_boot(struct vm_conf *conf, char *val)
{
	const char **p, *values[] = { "yes", "true", "oneshot", "always" };
	enum BOOT r[] = { YES, YES, ONESHOT, ALWAYS, NO };

	ARRAY_FOREACH (p, values)
		if (strcasecmp(val, *p) == 0)
			break;

	return set_boot(conf, r[p - values]);
}

static int
parse_hostbridge(struct vm_conf *conf, char *val)
{
	const char **p, *values[] = { "none", "standard", "intel", "amd" };
	enum HOSTBRIDGE_TYPE t[] = { NONE, INTEL, INTEL, AMD };

	ARRAY_FOREACH (p, values)
		if (strcasecmp(val, *p) == 0)
			break;

	if (p == &values[sizeof(values) / sizeof(values[0])])
		return -1;

	return set_hostbridge(conf, t[p - values]);
}

static int
parse_backend(struct vm_conf *conf, char *val)
{
	enum VM_BACKENDS b;

	if (strcasecmp(val, "bhyve") == 0)
		b = BHYVE;
	else if (strcasecmp(val, "qemu") == 0)
		b = QEMU;
	else
		return -1;

	return set_backend(conf, b);
}

static int
compare_archs(const void *a, const void *b)
{
	return strcasecmp((const char *)a, *(const char **)b);
}

static int
parse_qemu_arch(struct vm_conf *conf, char *val)
{
	const char **p,
	    *archs[] = { "aarch64", "alpha", "arm", "cris", "hppa", "i386",
		    "lm32", "m68k", "microblaze", "microblazeel", "mips",
		    "mips64", "mips64el", "mipsel", "moxie", "nios2", "or1k",
		    "ppc", "ppc64", "riscv32", "riscv64", "rx", "s390x", "sh4",
		    "sh4eb", "sparc", "sparc64", "tricore", "unicore32",
		    "x86_64", "xtensa", "xtensaeb" };

	if ((p = bsearch(val, archs, sizeof(archs) / sizeof(archs[0]),
		 sizeof(archs[0]), compare_archs)) == NULL)
		return -1;

	return set_qemu_arch(conf, *p);
}

static int
parse_qemu_machine(struct vm_conf *conf, char *val)
{
	return set_qemu_machine(conf, val);
}

static int
parse_keymap(struct vm_conf *conf, char *val)
{
	return set_keymap(conf, val);
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
	return set_comport(conf, val);
}

static bool
parse_boolean(const char *value)
{
	return (strcasecmp(value, "yes") == 0 ||
		strcasecmp(value, "true") == 0);
}

static int
parse_reboot_on_change(struct vm_conf *conf, char *val)
{
	return set_reboot_on_change(conf, parse_boolean(val));
}

static int
parse_install(struct vm_conf *conf, char *val)
{
	return set_install(conf, parse_boolean(val));
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

	if ((p = strchr(val, 'x')) == NULL)
		return -1;

	*p = '\0';

	if (parse_int(&width, val) < 0 || parse_int(&height, p + 1) < 0)
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

static int
parse_wired_memory(struct vm_conf *conf, char *val)
{
	return set_wired_memory(conf, parse_boolean(val));
}

static int
parse_utctime(struct vm_conf *conf, char *val)
{
	return set_utctime(conf, parse_boolean(val));
}

typedef int (*pfunc)(struct vm_conf *conf, char *val);
typedef void (*cfunc)(struct vm_conf *conf);

struct parser_entry {
	char *name;
	pfunc parse;
	cfunc clear;
};

/* must be sorted by name */
struct parser_entry parser_list[] = {
	{ "backend", &parse_backend, NULL },
	{ "boot", &parse_boot, NULL },
	{ "boot_delay", &parse_boot_delay, NULL },
	{ "comport", &parse_comport, NULL },
	{ "debug_port", &parse_debug_port, NULL },
	{ "disk", &parse_disk, &clear_disk_conf },
	{ "err_logfile", &parse_err_logfile, NULL },
	{ "graphics", &parse_graphics, NULL },
	{ "graphics_listen", &parse_graphics_listen, NULL },
	{ "graphics_password", &parse_graphics_password, NULL },
	{ "graphics_port", &parse_graphics_port, NULL },
	{ "graphics_res", &parse_graphics_res, NULL },
	{ "graphics_vga", &parse_graphics_vga, NULL },
	{ "graphics_wait", &parse_graphics_wait, NULL },
	{ "grub_run_partition", &parse_grub_run_partition, NULL },
	{ "hostbridge", &parse_hostbridge, NULL },
	{ "install", &parse_install, NULL },
	{ "installcmd", &parse_installcmd, NULL },
	{ "iso", &parse_iso, &clear_iso_conf },
	{ "keymap", &parse_keymap, NULL },
	{ "loadcmd", &parse_loadcmd, NULL },
	{ "loader", &parse_loader, NULL },
	{ "loader_timeout", &parse_loader_timeout, NULL },
	{ "memory", &parse_memory, NULL },
	{ "name", &parse_name, NULL },
	{ "ncpu", &parse_ncpu, NULL },
	{ "network", &parse_net, &clear_net_conf },
	{ "passthru", &parse_passthru, &clear_passthru_conf },
	{ "qemu_arch", &parse_qemu_arch, NULL },
	{ "qemu_machine", &parse_qemu_machine, NULL },
	{ "reboot_on_change", &parse_reboot_on_change, NULL },
	{ "stop_timeout", &parse_stop_timeout, NULL },
	{ "utctime", &parse_utctime, NULL },
	{ "wired_memory", &parse_wired_memory, NULL },
	{ "xhci_mouse", &parse_xhci_mouse, NULL },
};

static int
compare_parser_entry(const void *a, const void *b)
{
	const char *name = a;
	const struct parser_entry *ent = b;
	return strcasecmp(name, ent->name);
}

static int
parse(struct vm_conf *conf, FILE *fp, struct plugin_data_head *head)
{
	int rc;
	char *key;
	char *val;
	struct parser_entry *parser;
	char *name = conf->name;

	while (1) {
		if (get_token(fp, &key, NULL) == 1)
			break;
		if (key[0] == '\n') {
			free(key);
			continue;
		}

		if (get_token(fp, &val, NULL) == 1) {
			free(key);
			break;
		}
		if (val[0] != '=') {
			ERR("%s: value not found : %s\n", name, key);
			goto bad;
		}

		parser = bsearch(key, parser_list,
		    sizeof(parser_list) / sizeof(parser_list[0]),
		    sizeof(parser_list[0]), compare_parser_entry);
		free(val);
		if (parser && parser->clear != NULL)
			(*parser->clear)(conf);
		while (1) {
			if (get_token(fp, &val, conf) == 1)
				break;
			if (val[0] == '\n') {
				free(val);
				break;
			}

			if (key[0] == '$') {
				set_var(conf, &key[1], val);
				free(val);
				continue;
			}

			if (parser) {
				if ((*parser->parse)(conf, val) < 0) {
					ERR("%s: invalid value: %s = %s\n",
					    name, key, val);
					goto bad;
				}
			} else {
				rc = call_plugin_parser(head, key, val);
				if (rc > 0) {
					ERR("%s: unknown key %s\n",
					    name, key);
					goto bad;
				}
				if (rc < 0) {
					ERR("%s: invalid value: %s = %s\n",
					    name, key, val);
					goto bad;
				}
			}
			free(val);
		}
		free(key);
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

	if (conf->backend == BHYVE && conf->loader == NULL) {
		ERR("loader is required for vm %s\n", name);
		return -1;
	}

	return 0;
}

struct vm_conf *
parse_file(int fd, const char *filename, struct plugin_data_head *head)
{
	int ret;
	struct vm_conf *c;
	FILE *fp;

	if ((fp = fdopen(fd, "r")) == NULL)
		return NULL;

	if ((c = create_vm_conf(filename)) == NULL) {
		fclose(fp);
		return NULL;
	}

	ret = parse(c, fp, head);

	fdclose(fp, NULL);
	if (ret < 0 || finalize_vm_conf(c) < 0 || check_conf(c) < 0) {
		free_vm_conf(c);
		return NULL;
	}
	return c;
}
