/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2011 James Gritton.
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
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/jail.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <stdio.h>

STAILQ_HEAD(cfvars, cfvar);

enum CF_TYPE {
	CF_STR,
	CF_VAR,
	CF_EXPR,
	CF_NUM,
};

struct cfexpr {
	enum CF_TYPE		type;
	char			op, *val;
	struct cfexpr		*left, *right;
};

TAILQ_HEAD(cftokens, cftoken);

struct cftoken {
	TAILQ_ENTRY(cftoken)	next;
	enum CF_TYPE		type;
	char 			*s;
	size_t			len;
	struct cfexpr		*expr;
	char 			*filename;
	int 			lineno;
};

TAILQ_HEAD(cfvalues, cfvalue);

struct cfvalue {
	TAILQ_ENTRY(cfvalue)	next;
	struct cftokens		tokens;
};

TAILQ_HEAD(cfparams, cfparam);

struct cfparam {
	TAILQ_ENTRY(cfparam)	next;
	struct cftoken		*key;
	struct cfvalues		vals;
	int			operator;
};

TAILQ_HEAD(cfsections, cfsection);

struct cfsection {
	TAILQ_ENTRY(cfsection)	next;
	char			*name;
	struct cfparams		params;
	int			applied;
	int			duplicate;
	uid_t                   owner;
};

STAILQ_HEAD(cffiles, cffile);

struct cffile {
	FILE *fp;
	char *filename;
	int line;
	STAILQ_ENTRY(cffile) next;
};

void *emalloc(size_t);

int yyparse(void);
void yyerror(const char *);
int yylex(void);
void yyerror(const char *);
int yylex_destroy(void);

void glob_path(struct cftokens *ts);
int apply_global_vars(struct cfsection *sc);
char *peek_filename();
uid_t peek_fileowner();
