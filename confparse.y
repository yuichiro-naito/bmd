%{
/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2011 James Gritton
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <stdlib.h>
#include <string.h>

#include "confparse.h"
#include "log.h"

#ifdef DEBUG
#define YYDEBUG 1
#endif

#define YY_NO_LEAKS

enum SECTION {
	 SECTION_GLOBAL,
	 SECTION_TEMPLATE,
	 SECTION_VM
};

extern int lineno;

static void free_all_cfsections();
%}

%union {
	struct cfsection	*sc;
	struct cfparams		*pp;
	struct cfparam		*p;
	struct cfvalues		*vs;
	struct cfvalue		*vl;
	struct cftokens		*ts;
	struct cftoken		*tk;
	struct cfexpr		*ex;
	struct cfarg            *ag;
	struct cfargs           *as;
	struct cfargdef         *ad;
	struct cfargdefs        *ds;
	char			*cs;
}

%token      GLOBAL VM TEMPLATE PLEQ BEGIN_AR END_AR INCLUDE
%token <cs> STR VAR NUMBER APPLY

%type <sc> tmpl global vm
%type <pp> param_l
%type <p>  param
%type <vs> values targets
%type <vl> value target
%type <ts> tokens
%type <tk> name macro
%type <ex> expr
%type <ag> arg
%type <as> args
%type <ad> argdef
%type <ds> argdefs
%%


/*
 * A config file consts of 3 types of sections and .include macro;
 */
conf	:
	;
	| conf global
	| conf tmpl
	| conf vm
	| conf include
	;
global	: GLOBAL '{' param_l '}'
	{
		if (($$ = add_section(SECTION_GLOBAL, NULL)) == NULL) {
			free_cfparams($3);
			free_all_cfsections();
			goto yyabort;
		}
		STAILQ_CONCAT(&$$->params, $3);
		free($3);
		apply_global_vars($$);  /* for .include macro */
	}
	;
tmpl	: TEMPLATE STR '{' param_l '}'
	{
		if (($$ = add_section(SECTION_TEMPLATE, $2)) == NULL) {
			free_cfparams($4);
			free_all_cfsections();
			goto yyabort;
		}
		STAILQ_CONCAT(&$$->params, $4);
		free($4);
	}
	| TEMPLATE STR '(' argdefs ')' '{' param_l '}'
	{
		if (($$ = add_section(SECTION_TEMPLATE, $2)) == NULL) {
			free_cfargdefs($4);
			free_cfparams($7);
			free_all_cfsections();
			goto yyabort;
		}
		STAILQ_CONCAT(&$$->argdefs, $4);
		free($4);
		STAILQ_CONCAT(&$$->params, $7);
		free($7);
	}
	;
argdefs : argdef
	{
		if (($$ = emalloc(sizeof(struct cfargdefs))) == NULL) {
			free_cfargdef($1);
			free_all_cfsections();
			goto yyabort;
		}
		STAILQ_INIT($$);
		STAILQ_INSERT_TAIL($$, $1, next);
	}
	| argdefs ',' argdef
	{
		$$ = $1;
		STAILQ_INSERT_TAIL($$, $3, next);
	}
	;
argdef	: STR
	{
		if (($$ = emalloc(sizeof(struct cfargdef))) == NULL) {
			free($1);
			free_all_cfsections();
			goto yyabort;
		}
		$$->name = $1;
		STAILQ_INIT(&$$->tokens);
	}
	| STR '=' tokens
	{
		if (($$ = emalloc(sizeof(struct cfargdef))) == NULL) {
			free($1);
			free_cftokens($3);
			free_all_cfsections();
			goto yyabort;
		}
		$$->name = $1;
		STAILQ_INIT(&$$->tokens);
		STAILQ_CONCAT(&$$->tokens, $3);
		free($3);
	}
	;
vm	: VM STR '{' param_l '}'
	{
		if (($$ = add_section(SECTION_VM, $2)) == NULL) {
			free_cfparams($4);
			free_all_cfsections();
			goto yyabort;
		}
		STAILQ_CONCAT(&$$->params, $4);
		free($4);
	}
	;
include	: INCLUDE tokens ';'
	{
		glob_path($2);
	}
	;
param_l	:
	{
		if (($$ = emalloc(sizeof(struct cfparams))) == NULL) {
			free_all_cfsections();
			goto yyabort;
		}
		STAILQ_INIT($$);
	}
	| param_l param ';'
	{
		$$ = $1;
		STAILQ_INSERT_TAIL($$, $2, next);
	}
	;

/*
 * Parameters have a name and an list of values,
 * which may have "+=" or "=" preceding them.
 * Macros have target parameters which includes optional arguments.
 */
param	: macro targets
	{
		if (($$ = emalloc(sizeof(struct cfparam))) == NULL) {
			free_cftoken($1);
			free_cfvalues($2);
			free_all_cfsections();
			goto yyabort;
		}
		$$->operator = 0;
		$$->key = $1;
		STAILQ_INIT(&$$->vals);
		STAILQ_CONCAT(&$$->vals, $2);
		free($2);
	}
	| name '=' values
	{
		if (($$ = emalloc(sizeof(struct cfparam))) == NULL) {
			free_cftoken($1);
			free_cfvalues($3);
			free_all_cfsections();
			goto yyabort;
		}
		$$->operator = 0;
		$$->key = $1;
		STAILQ_INIT(&$$->vals);
		STAILQ_CONCAT(&$$->vals, $3);
		free($3);
	}
	| name PLEQ values
	{
		if (($$ = emalloc(sizeof(struct cfparam))) == NULL) {
			free_cftoken($1);
			free_cfvalues($3);
			free_all_cfsections();
			goto yyabort;
		}
		$$->operator = 1;
		$$->key = $1;
		STAILQ_INIT(&$$->vals);
		STAILQ_CONCAT(&$$->vals, $3);
		free($3);
	}
	| error
	{
		if (($$ = emalloc(sizeof(struct cfparam))) == NULL) {
			free_all_cfsections();
			goto yyabort;
		}
		$$->operator = -1;
		$$->key = NULL;
		STAILQ_INIT(&$$->vals);
	}
	;

/*
 * A parameter has a fixed name.  A variable definition looks just like a
 * parameter except that the name is a variable.
 */
macro	: APPLY
	{
		if ($1 == NULL || ($$ = create_token(CF_STR)) == NULL) {
			free($1);
			free_all_cfsections();
			goto yyabort;
		}
		$$->s = $1;
		$$->len = strlen($1);
		$$->expr = NULL;
		STAILQ_NEXT($$, next) = NULL;
	}
	;
name	: STR
	{
		if ($1 == NULL || ($$ = create_token(CF_STR)) == NULL) {
			free($1);
			free_all_cfsections();
			goto yyabort;
		}
		$$->s = $1;
		$$->len = strlen($1);
		$$->expr = NULL;
		STAILQ_NEXT($$, next) = NULL;
	}
	| VAR
	{
		if ($1 == NULL || ($$ = create_token(CF_VAR)) == NULL) {
			free($1);
			free_all_cfsections();
			goto yyabort;
		}
		$$->s = $1;
		$$->len = strlen($1);
		$$->expr = NULL;
		STAILQ_NEXT($$, next) = NULL;
	}
	;
values	: value
	{
		if (($$ = emalloc(sizeof(struct cfvalues))) == NULL) {
			free_cfvalue($1);
			free_all_cfsections();
			goto yyabort;
		}
		STAILQ_INIT($$);
		STAILQ_INSERT_TAIL($$, $1, next);
	}
	| values ',' value
	{
		$$ = $1;
		STAILQ_INSERT_TAIL($$, $3, next);
	}
	;
value	: tokens
	{
		if (($$ = emalloc(sizeof(struct cfvalue))) == NULL) {
			free_cftokens($1);
			free_all_cfsections();
			goto yyabort;
		}
		STAILQ_INIT(&$$->tokens);
		STAILQ_CONCAT(&$$->tokens, $1);
		free($1);
		STAILQ_INIT(&$$->args);
		STAILQ_NEXT($$, next) = NULL;
	}
	;
targets	: target
	{
		if (($$ = emalloc(sizeof(struct cfvalues))) == NULL) {
			free_cfvalue($1);
			free_all_cfsections();
			goto yyabort;
		}
		STAILQ_INIT($$);
		STAILQ_INSERT_TAIL($$, $1, next);
	}
	| targets ',' target
	{
		$$ = $1;
		STAILQ_INSERT_TAIL($$, $3, next);
	}
	;
target	: tokens
	{
		if (($$ = emalloc(sizeof(struct cfvalue))) == NULL) {
			free_cftokens($1);
			free_all_cfsections();
			goto yyabort;
		}
		STAILQ_INIT(&$$->tokens);
		STAILQ_CONCAT(&$$->tokens, $1);
		free($1);
		STAILQ_INIT(&$$->args);
		STAILQ_NEXT($$, next) = NULL;
	}
	| tokens '(' args ')'
	{
		if (($$ = emalloc(sizeof(struct cfvalue))) == NULL) {
			free_cftokens($1);
			free_all_cfsections();
			goto yyabort;
		}
		STAILQ_INIT(&$$->tokens);
		STAILQ_CONCAT(&$$->tokens, $1);
		free($1);
		STAILQ_INIT(&$$->args);
		STAILQ_CONCAT(&$$->args, $3);
		free($3);
		STAILQ_NEXT($$, next) = NULL;
	}
	;
args	: arg
	{
		if (($$ = emalloc(sizeof(struct cfargs))) == NULL) {
			free_cfarg($1);
			free_all_cfsections();
			goto yyabort;
		}
		STAILQ_INIT($$);
		STAILQ_INSERT_TAIL($$, $1, next);
	}
	| args ',' arg
	{
		$$ = $1;
		STAILQ_INSERT_TAIL($$, $3, next);
	}
	;
arg	: tokens
	{
		if (($$ = emalloc(sizeof(struct cfarg))) == NULL) {
			free_cftokens($1);
			free_all_cfsections();
			goto yyabort;
		}
		STAILQ_INIT(&$$->tokens);
		STAILQ_CONCAT(&$$->tokens, $1);
		free($1);
		STAILQ_NEXT($$, next) = NULL;
	}
	;

/*
 * Strings may be passed in pieces, because of quoting and/or variable
 * interpolation. Make a linked list for strings and a tree for arithmetic
 * expressions.
 */
tokens	:
	{
		if (($$ = emalloc(sizeof(struct cftokens))) == NULL) {
			free_all_cfsections();
			goto yyabort;
		}
		STAILQ_INIT($$);
	}
	| tokens BEGIN_AR expr END_AR
	{
		struct cftoken *ct;
		$$ = $1;
		if ((ct = create_token(CF_EXPR)) == NULL) {
			free_cftokens($1);
			free_cfexpr($3);
			free_all_cfsections();
			goto yyabort;
		}
		ct->s = NULL;
		ct->len = 0;
		ct->expr = $3;
		STAILQ_INSERT_TAIL($$, ct, next);
	}
	| tokens STR
	{
		struct cftoken *ct;
		$$ = $1;
		if ($2 == NULL || (ct = create_token(CF_STR)) == NULL) {
			free_cftokens($1);
			free($2);
			free_all_cfsections();
			goto yyabort;
		}
		ct->s = $2;
		ct->len = strlen($2);
		ct->expr = NULL;
		STAILQ_INSERT_TAIL($$, ct, next);
	}
	| tokens VAR
	{
		struct cftoken *ct;
		$$ = $1;
		if ($2 == NULL | (ct = create_token(CF_VAR)) == NULL) {
			free_cftokens($1);
			free($2);
			free_all_cfsections();
			goto yyabort;
		}
		ct->s = $2;
		ct->len = strlen($2);
		ct->expr = NULL;
		STAILQ_INSERT_TAIL($$, ct, next);
	}
	;
/*
 * Arithmetic expressions.
 */
expr	: NUMBER
	{
		if ($1 == NULL ||
		    ($$ = emalloc(sizeof(struct cfexpr))) == NULL) {
			free($1);
			free_all_cfsections();
			goto yyabort;
		}
		$$->type = CF_NUM;
		$$->op = '\0';
		$$->left = NULL;
		$$->right = NULL;
		$$->val = $1;
	}
	| VAR
	{
		if ($1 == NULL ||
		    ($$ = emalloc(sizeof(struct cfexpr))) == NULL) {
			free($1);
			free_all_cfsections();
			goto yyabort;
		}
		$$->type = CF_VAR;
		$$->op = '\0';
		$$->left = NULL;
		$$->right = NULL;
		$$->val = $1;
	}
	| expr '+' expr
	{
		if (($$ = emalloc(sizeof(struct cfexpr))) == NULL) {
			free_cfexpr($1);
			free_cfexpr($3);
			free_all_cfsections();
			goto yyabort;
		}
		$$->type = CF_EXPR;
		$$->op = '+';
		$$->left = $1;
		$$->right = $3;
		$$->val = NULL;
	}
	| expr '-' expr
	{
		if (($$ = emalloc(sizeof(struct cfexpr))) == NULL) {
			free_cfexpr($1);
			free_cfexpr($3);
			free_all_cfsections();
			goto yyabort;
		}
		$$->type = CF_EXPR;
		$$->op = '-';
		$$->left = $1;
		$$->right = $3;
		$$->val = NULL;
	}
	| expr '*' expr
	{
		if (($$ = emalloc(sizeof(struct cfexpr))) == NULL) {
			free_cfexpr($1);
			free_cfexpr($3);
			free_all_cfsections();
			goto yyabort;
		}
		$$->type = CF_EXPR;
		$$->op = '*';
		$$->left = $1;
		$$->right = $3;
		$$->val = NULL;
	}
	| expr '/' expr
	{
		if (($$ = emalloc(sizeof(struct cfexpr))) == NULL) {
			free_cfexpr($1);
			free_cfexpr($3);
			free_all_cfsections();
			goto yyabort;
		}
		$$->type = CF_EXPR;
		$$->op = '/';
		$$->left = $1;
		$$->right = $3;
		$$->val = NULL;
	}
	| expr '%' expr
	{
		if (($$ = emalloc(sizeof(struct cfexpr))) == NULL) {
			free_cfexpr($1);
			free_cfexpr($3);
			free_all_cfsections();
			goto yyabort;
		}
		$$->type = CF_EXPR;
		$$->op = '%';
		$$->left = $1;
		$$->right = $3;
		$$->val = NULL;
	}
	| '-' '(' expr ')'
	{
		if (($$ = emalloc(sizeof(struct cfexpr))) == NULL) {
			free_cfexpr($3);
			free_all_cfsections();
			goto yyabort;
		}
		$$->type = CF_EXPR;
		$$->op = '~';
		$$->left = $3;
		$$->right = NULL;
		$$->val = NULL;
	}
	| '-' NUMBER
	{
		struct cfexpr *n;
		$$ = emalloc(sizeof(struct cfexpr));
		n = emalloc(sizeof(struct cfexpr));
		if ($2 == NULL || $$ == NULL || n == NULL) {
			free($2);
			free_cfexpr($$);
			free_cfexpr(n);
			free_all_cfsections();
			goto yyabort;
		}
		n->type = CF_NUM;
		n->op = '\0';
		n->left = NULL;
		n->right = NULL;
		n->val = $2;

		$$->type = CF_EXPR;
		$$->op = '~';
		$$->left = n;
		$$->right = NULL;
		$$->val = NULL;
	}
	| '-' VAR
	{
		struct cfexpr *v;
		$$ = emalloc(sizeof(struct cfexpr));
		v = emalloc(sizeof(struct cfexpr));
		if ($2 == NULL || $$ == NULL || v == NULL) {
			free($2);
			free_cfexpr($$);
			free_cfexpr(v);
			free_all_cfsections();
			goto yyabort;
		}
		v->type = CF_VAR;
		v->op = '\0';
		v->left = NULL;
		v->right = NULL;
		v->val = $2;

		$$->type = CF_EXPR;
		$$->op = '~';
		$$->left = v;
		$$->right = NULL;
		$$->val = NULL;
	}
	| '(' expr ')'
	{
		$$ = $2;
	}
	;
%%

struct parser_context *pctxt;

static void
free_all_cfsections()
{
	struct cfsection *sc, *sn;

	STAILQ_FOREACH_SAFE(sc, &pctxt->cfglobals, next, sn)
		free_cfsection(sc);
	STAILQ_FOREACH_SAFE(sc, &pctxt->cftemplates, next, sn)
		free_cfsection(sc);
	STAILQ_FOREACH_SAFE(sc, &pctxt->cfvms, next, sn)
		free_cfsection(sc);
}

struct cfsection *
add_section(enum SECTION sec, char *name)
{
	static struct cfsections *section;
	static char *sec_names[] = {"global", "template", "vm"};
	struct cfsection *v;

	switch (sec) {
	case SECTION_GLOBAL:
		section = &pctxt->cfglobals;
		break;
	case SECTION_TEMPLATE:
		section = &pctxt->cftemplates;
		break;
	case SECTION_VM:
		section = &pctxt->cfvms;
		break;
	}

	if (name != NULL && sec != SECTION_GLOBAL)
		STAILQ_FOREACH (v, section, next)
			if (strcmp(v->name, name) == 0) {
				ERR("%s: %s '%s' already exists.",
				    peek_filename(), sec_names[sec], name);
				v->duplicate++;
				break;
			}

	if ((v = emalloc(sizeof(*v))) == NULL)
		return NULL;
	memset(v, 0, sizeof(*v));
	v->name = name;
	v->owner = peek_fileowner();
	v->filename = peek_filename();
	STAILQ_INIT(&v->params);
	STAILQ_INIT(&v->argdefs);
	STAILQ_INSERT_TAIL(section, v, next);
	return v;
}

void *
emalloc(size_t size)
{
	void *p;

	if ((p = malloc(size)) == NULL)
		ERR("%s\n", "fail to allocate memory for parser");
	return p;
}

struct cftoken*
create_token(enum CF_TYPE t)
{
	struct cftoken *tk;

	if ((tk = emalloc(sizeof(struct cftoken))) == NULL)
		return NULL;

	tk->type = t;
	tk->filename = peek_filename();
	tk->lineno = lineno;
	return tk;
}
