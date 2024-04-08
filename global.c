#include <string.h>
#include <stdlib.h>
#include "conf.h"
#include "server.h"
#include "bmd.h"
#include "bmd_plugin.h"

/*
  Default global configuration.
 */
static char gl0_config_file[] = LOCALBASE "/etc/bmd.conf";
static char gl0_plugin_dir[] = LOCALBASE "/libexec/bmd";
static char gl0_vars_dir[] = LOCALBASE "/var/cache/bmd";
static char gl0_pid_path[] = "/var/run/bmd.pid";
static char gl0_cmd_sock_path[] = "/var/run/bmd.sock";
static char gl0_cmd_sock_mode[] = "0600";
static struct global_conf gl_conf0 = {
	.config_file = gl0_config_file,
	.plugin_dir = gl0_plugin_dir,
	.vars_dir = gl0_vars_dir,
	.pid_path = gl0_pid_path,
	.cmd_sock_path = gl0_cmd_sock_path,
	.unix_domain_socket_mode = gl0_cmd_sock_mode,
	.nmdm_offset = DEFAULT_NMDM_OFFSET,
	.foreground = 0
};

struct global_conf *gl_conf = &gl_conf0;

void
free_global_conf(struct global_conf *gc)
{
	free(gc->config_file);
	free(gc->pid_path);
	free(gc->plugin_dir);
	free(gc->vars_dir);
	free(gc->cmd_sock_path);
	free(gc->unix_domain_socket_mode);
	free(gc);
}

void
free_gl_conf(void)
{
	free_global_conf(gl_conf);
	gl_conf = &gl_conf0;
}

int
init_gl_conf(void)
{
	struct global_conf *t;
	if ((t = calloc(1, sizeof(*t))) == NULL)
		return -1;
#define COPY_ATTR_STRING(attr) \
	if (gl_conf0.attr != NULL &&				\
	    (t->attr = strdup(gl_conf0.attr)) == NULL)		\
		goto err;
#define COPY_ATTR_INT(attr) t->attr = gl_conf0.attr

	COPY_ATTR_STRING(config_file);
	COPY_ATTR_STRING(pid_path);
	COPY_ATTR_STRING(plugin_dir);
	COPY_ATTR_STRING(vars_dir);
	COPY_ATTR_STRING(cmd_sock_path);
	COPY_ATTR_STRING(unix_domain_socket_mode);
	COPY_ATTR_INT(nmdm_offset);
	COPY_ATTR_INT(foreground);
#undef COPY_ATTR_STRING
#undef COPY_ATTR_INT

	gl_conf = t;
	return 0;

err:
	free_global_conf(t);
	return -1;
}

int
merge_global_conf(struct global_conf *gc)
{
#define REPLACE_STR(attr)	\
	if (gc->attr) {							\
		if (gl_conf->attr)					\
			free(gl_conf->attr);				\
		gl_conf->attr = gc->attr;				\
		gc->attr = NULL;					\
	}
#define REPLACE_INT(attr)  \
	if (gc->attr != 0)			\
		gl_conf->attr = gc->attr;

	REPLACE_STR(config_file);
	REPLACE_STR(pid_path);
	REPLACE_STR(plugin_dir);
	REPLACE_STR(vars_dir);
	REPLACE_STR(cmd_sock_path);
	REPLACE_STR(unix_domain_socket_mode);
	REPLACE_INT(nmdm_offset);
#undef REPLACE_INT
#undef REPLACE_STR

	free(gc);
	return 0;
}
