/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Yuichiro Naito
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _VM_H_
#define _VM_H_

#include "bmd_plugin.h"

struct vm;
struct vm_conf;

#define PLUGIN_MODULE_VAR(v)					\
	static PLUGIN_DESC(v) __used __section("plugin_array")
#define PLUGIN_METHOD_MODULE(n, v, l) PLUGIN_MODULE_VAR(pl_desc_##n) = { \
		.version = PLUGIN_VERSION, .name = (#n), .method = (v),	\
		.loader_method = (l) }
#define PLUGIN_VM_METHOD(n, s, r, p, a, c) \
	static struct vm_method(n) = { .name = (#n), .vm_start = (s), \
		.vm_reset = (r), .vm_poweroff = (p), \
		.vm_acpi_poweroff = (a), .vm_cleanup = (c) }
#define PLUGIN_LOADER_METHOD(n, l, c) static struct loader_method(n) = { \
		.name = (#n), .ld_load = (l), .ld_cleanup = (c) }

/* Implemented in vm.c */
int remove_taps(struct vm *);
int activate_taps(struct vm *);
int assign_taps(struct vm *);
ssize_t writen(int, const void *, size_t);
int write_err_log(int, struct vm *);
int write_mapfile(struct vm_conf *, char **);
char **split_args(char *);

/* Implemented in tap.c */
int add_to_bridge(int, const char *, const char *);
int activate_tap(int, const char *);
int create_tap(int, char **);
int destroy_tap(int, const char *);
int set_tap_description(int, const char *, char *);

#endif
