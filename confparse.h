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

#include "y.tab.h"

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

STAILQ_HEAD(cftokens, cftoken);

struct cftoken {
	STAILQ_ENTRY(cftoken)	next;
	enum CF_TYPE		type;
	char 			*s;
	size_t			len;
	struct cfexpr		*expr;
	char 			*filename;
	int 			lineno;
};

STAILQ_HEAD(cfargdefs, cfargdef);

struct cfargdef {
	STAILQ_ENTRY(cfargdef)   next;
	char                     *name;
	struct cftokens		tokens;
};

STAILQ_HEAD(cfargs, cfarg);

struct cfarg {
	STAILQ_ENTRY(cfarg)      next;
	struct cftokens		tokens;
};

STAILQ_HEAD(cfvalues, cfvalue);

struct cfvalue {
	STAILQ_ENTRY(cfvalue)	next;
	struct cftokens		tokens;
	struct cfargs           args;
};

STAILQ_HEAD(cfparams, cfparam);

struct cfparam {
	STAILQ_ENTRY(cfparam)	next;
	struct cftoken		*key;
	struct cfvalues		vals;
	int			operator;
};

STAILQ_HEAD(cfsections, cfsection);

struct cfsection {
	STAILQ_ENTRY(cfsection)	next;
	char			*name;
	struct cfparams		params;
	struct cfargdefs        argdefs;
	int			applied;
	int			duplicate;
	uid_t                   owner;
	char                    *filename;
};

STAILQ_HEAD(cffiles, cffile);

struct cffile {
	char *filename;
	int line;
	STAILQ_ENTRY(cffile) next;
};

enum mpool_error {
	MPERR_NONE,
	MPERR_ALLOC,
	MPERR_FATAL
};

STAILQ_HEAD(mpools, mpool);

struct mpool {
	STAILQ_ENTRY(mpool) next;
	void *end;
	void *used;
	void *last_used;
	enum mpool_error   error_number;
	int   dummy;
	char data[0];
};

#define DEFAULT_MMAP_SIZE  (PAGE_SIZE * 64)

struct parser_context {
	struct cfsections cfglobals;
	struct cfsections cftemplates;
	struct cfsections cfvms;
	struct cffiles    cffiles;
	struct cffile    *cur_file;
};

extern int yydebug;
extern int yyerrflag;
extern int yychar;
extern int yynerrs;
extern YYSTYPE yyval;
extern FILE *yyin;
extern int lineno;
extern struct parser_context *pctxt, *pctxt_snapshot;

int yyparse(void);
void yyerror(const char *);
int yylex(void);
void yyerror(const char *);
int yylex_destroy(void);

void glob_path(struct cftokens *);
int apply_global_vars(struct cfsection *);
char *peek_filename(void);
uid_t peek_fileowner(void);

void *mpool_alloc(size_t);
#define objalloc(t)    mpool_alloc(sizeof(struct t))

void free_cfexpr(struct cfexpr *);
void free_cftoken(struct cftoken *);
void free_cftokens(struct cftokens *);
void free_cfvalue(struct cfvalue *);
void free_cfvalues(struct cfvalues *);
void free_cfparam(struct cfparam *);
void free_cfparams(struct cfparams *);
void free_cfsection(struct cfsection *);
void free_cfsections(struct cfsections *);
void free_cfarg(struct cfarg *);
void free_cfargs(struct cfargs *);
void free_cfargdef(struct cfargdef *);
void free_cfargdefs(struct cfargdefs *);
