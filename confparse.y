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
		if (($$ = add_section(SECTION_GLOBAL, NULL)) == NULL)
			goto yyabort;
		STAILQ_CONCAT(&$$->params, $3);
		apply_global_vars($$);  /* for .include macro */
	}
	;
tmpl	: TEMPLATE STR '{' param_l '}'
	{
		if (($$ = add_section(SECTION_TEMPLATE, $2)) == NULL)
			goto yyabort;
		STAILQ_CONCAT(&$$->params, $4);
	}
	| TEMPLATE STR '(' argdefs ')' '{' param_l '}'
	{
		if (($$ = add_section(SECTION_TEMPLATE, $2)) == NULL)
			goto yyabort;
		STAILQ_CONCAT(&$$->argdefs, $4);
		STAILQ_CONCAT(&$$->params, $7);
	}
	;
argdefs : argdef
	{
		if (($$ = objalloc(cfargdefs)) == NULL)
			goto yyabort;
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
		if (($$ = objalloc(cfargdef)) == NULL)
			goto yyabort;
		$$->name = $1;
		STAILQ_INIT(&$$->tokens);
	}
	| STR '=' tokens
	{
		if (($$ = objalloc(cfargdef)) == NULL)
			goto yyabort;
		$$->name = $1;
		STAILQ_INIT(&$$->tokens);
		STAILQ_CONCAT(&$$->tokens, $3);
	}
	;
vm	: VM STR '{' param_l '}'
	{
		if (($$ = add_section(SECTION_VM, $2)) == NULL)
			goto yyabort;
		STAILQ_CONCAT(&$$->params, $4);
	}
	;
include	: INCLUDE tokens ';'
	{
		glob_path($2);
	}
	;
param_l	:
	{
		if (($$ = objalloc(cfparams)) == NULL)
			goto yyabort;
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
		if (($$ = objalloc(cfparam)) == NULL)
			goto yyabort;
		$$->operator = 0;
		$$->key = $1;
		STAILQ_INIT(&$$->vals);
		STAILQ_CONCAT(&$$->vals, $2);
	}
	| name '=' values
	{
		if (($$ = objalloc(cfparam)) == NULL)
			goto yyabort;
		$$->operator = 0;
		$$->key = $1;
		STAILQ_INIT(&$$->vals);
		STAILQ_CONCAT(&$$->vals, $3);
	}
	| name PLEQ values
	{
		if (($$ = objalloc(cfparam)) == NULL)
			goto yyabort;
		$$->operator = 1;
		$$->key = $1;
		STAILQ_INIT(&$$->vals);
		STAILQ_CONCAT(&$$->vals, $3);
	}
	| error
	{
		if (($$ = objalloc(cfparam)) == NULL)
			goto yyabort;
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
		if ($1 == NULL || ($$ = create_token(CF_STR)) == NULL)
			goto yyabort;
		$$->s = $1;
		$$->len = strlen($1);
		$$->expr = NULL;
		STAILQ_NEXT($$, next) = NULL;
	}
	;
name	: STR
	{
		if ($1 == NULL || ($$ = create_token(CF_STR)) == NULL)
			goto yyabort;
		$$->s = $1;
		$$->len = strlen($1);
		$$->expr = NULL;
		STAILQ_NEXT($$, next) = NULL;
	}
	| VAR
	{
		if ($1 == NULL || ($$ = create_token(CF_VAR)) == NULL)
			goto yyabort;
		$$->s = $1;
		$$->len = strlen($1);
		$$->expr = NULL;
		STAILQ_NEXT($$, next) = NULL;
	}
	;
values	: value
	{
		if (($$ = objalloc(cfvalues)) == NULL)
			goto yyabort;
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
		if (($$ = objalloc(cfvalue)) == NULL)
			goto yyabort;
		STAILQ_INIT(&$$->tokens);
		STAILQ_CONCAT(&$$->tokens, $1);
		STAILQ_INIT(&$$->args);
		STAILQ_NEXT($$, next) = NULL;
	}
	;
targets	: target
	{
		if (($$ = objalloc(cfvalues)) == NULL)
			goto yyabort;
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
		if (($$ = objalloc(cfvalue)) == NULL)
			goto yyabort;
		STAILQ_INIT(&$$->tokens);
		STAILQ_CONCAT(&$$->tokens, $1);
		STAILQ_INIT(&$$->args);
		STAILQ_NEXT($$, next) = NULL;
	}
	| tokens '(' args ')'
	{
		if (($$ = objalloc(cfvalue)) == NULL)
			goto yyabort;
		STAILQ_INIT(&$$->tokens);
		STAILQ_CONCAT(&$$->tokens, $1);
		STAILQ_INIT(&$$->args);
		STAILQ_CONCAT(&$$->args, $3);
		STAILQ_NEXT($$, next) = NULL;
	}
	;
args	: arg
	{
		if (($$ = objalloc(cfargs)) == NULL)
			goto yyabort;
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
		if (($$ = objalloc(cfarg)) == NULL)
			goto yyabort;
		STAILQ_INIT(&$$->tokens);
		STAILQ_CONCAT(&$$->tokens, $1);
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
		if (($$ = objalloc(cftokens)) == NULL)
			goto yyabort;
		STAILQ_INIT($$);
	}
	| tokens BEGIN_AR expr END_AR
	{
		struct cftoken *ct;
		$$ = $1;
		if ((ct = create_token(CF_EXPR)) == NULL)
			goto yyabort;
		ct->s = NULL;
		ct->len = 0;
		ct->expr = $3;
		STAILQ_INSERT_TAIL($$, ct, next);
	}
	| tokens STR
	{
		struct cftoken *ct;
		$$ = $1;
		if ($2 == NULL || (ct = create_token(CF_STR)) == NULL)
			goto yyabort;
		ct->s = $2;
		ct->len = strlen($2);
		ct->expr = NULL;
		STAILQ_INSERT_TAIL($$, ct, next);
	}
	| tokens VAR
	{
		struct cftoken *ct;
		$$ = $1;
		if ($2 == NULL | (ct = create_token(CF_VAR)) == NULL)
			goto yyabort;
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
		    ($$ = objalloc(cfexpr)) == NULL)
			goto yyabort;
		$$->type = CF_NUM;
		$$->op = '\0';
		$$->left = NULL;
		$$->right = NULL;
		$$->val = $1;
	}
	| VAR
	{
		if ($1 == NULL || ($$ = objalloc(cfexpr)) == NULL)
			goto yyabort;
		$$->type = CF_VAR;
		$$->op = '\0';
		$$->left = NULL;
		$$->right = NULL;
		$$->val = $1;
	}
	| expr '+' expr
	{
		if (($$ = objalloc(cfexpr)) == NULL)
			goto yyabort;
		$$->type = CF_EXPR;
		$$->op = '+';
		$$->left = $1;
		$$->right = $3;
		$$->val = NULL;
	}
	| expr '-' expr
	{
		if (($$ = objalloc(cfexpr)) == NULL)
			goto yyabort;
		$$->type = CF_EXPR;
		$$->op = '-';
		$$->left = $1;
		$$->right = $3;
		$$->val = NULL;
	}
	| expr '*' expr
	{
		if (($$ = objalloc(cfexpr)) == NULL)
			goto yyabort;
		$$->type = CF_EXPR;
		$$->op = '*';
		$$->left = $1;
		$$->right = $3;
		$$->val = NULL;
	}
	| expr '/' expr
	{
		if (($$ = objalloc(cfexpr)) == NULL)
			goto yyabort;
		$$->type = CF_EXPR;
		$$->op = '/';
		$$->left = $1;
		$$->right = $3;
		$$->val = NULL;
	}
	| expr '%' expr
	{
		if (($$ = objalloc(cfexpr)) == NULL)
			goto yyabort;
		$$->type = CF_EXPR;
		$$->op = '%';
		$$->left = $1;
		$$->right = $3;
		$$->val = NULL;
	}
	| '-' '(' expr ')'
	{
		if (($$ = objalloc(cfexpr)) == NULL)
			goto yyabort;
		$$->type = CF_EXPR;
		$$->op = '~';
		$$->left = $3;
		$$->right = NULL;
		$$->val = NULL;
	}
	| '-' NUMBER
	{
		struct cfexpr *n;
		$$ = objalloc(cfexpr);
		n = objalloc(cfexpr);
		if ($2 == NULL || $$ == NULL || n == NULL)
			goto yyabort;
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
		$$ = objalloc(cfexpr);
		v = objalloc(cfexpr);
		if ($2 == NULL || $$ == NULL || v == NULL)
			goto yyabort;
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

struct parser_context *pctxt, *pctxt_snapshot;

struct cfsection *
add_section(enum SECTION sec, char *name)
{
	static struct cfsections *section;
	static char *sec_names[] = { "global", "template", "vm" };
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

	if ((v = objalloc(cfsection)) == NULL)
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

struct cftoken *
create_token(enum CF_TYPE t)
{
	struct cftoken *tk;

	if ((tk = objalloc(cftoken)) == NULL)
		return NULL;

	tk->type = t;
	tk->filename = peek_filename();
	tk->lineno = lineno;
	return tk;
}
