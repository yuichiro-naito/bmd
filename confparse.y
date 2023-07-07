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
	char			*cs;
}

%token      GLOBAL VM TEMPLATE PLEQ BEGIN_AR END_AR INCLUDE
%token <cs> STR STR1 VAR VAR1 NUMBER APPLY

%type <sc> tmpl global vm
%type <pp> param_l
%type <p>  param
%type <vs> values
%type <vl> value
%type <ts> tokens
%type <tk> name macro
%type <ex> expr
%%


/*
 * A config file is a series of jails (containing parameters) and jail-less
 * parameters which really belong to a global pseudo-jail.
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
		$$ = add_section(SECTION_GLOBAL, NULL);
		TAILQ_CONCAT(&$$->params, $3, next);
		free($3);
		apply_global_vars($$);  /* for .include macro */
	}
tmpl	: TEMPLATE STR '{' param_l '}'
	{
		$$ = add_section(SECTION_TEMPLATE, $2);
		TAILQ_CONCAT(&$$->params, $4, next);
		free($4);
	}
vm	: VM STR '{' param_l '}'
	{
		$$ = add_section(SECTION_VM, $2);
		TAILQ_CONCAT(&$$->params, $4, next);
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
		$$ = emalloc(sizeof(struct cfparams));
		TAILQ_INIT($$);
	}
	| param_l param ';'
	{
		$$ = $1;
		TAILQ_INSERT_TAIL($$, $2, next);
	}
	| param_l ';'
	{
		$$ = $1;
	}
	;

/*
 * Parameters have a name and an optional list of value strings,
 * which may have "+=" or "=" preceding them.
 */
param	: macro values
	{
		$$ = emalloc(sizeof(struct cfparam));
		$$->operator = 0;
		$$->key = $1;
		TAILQ_INIT(&$$->vals);
		TAILQ_CONCAT(&$$->vals, $2, next);
		free($2);
	}
	| name '=' values
	{
		$$ = emalloc(sizeof(struct cfparam));
		$$->operator = 0;
		$$->key = $1;
		TAILQ_INIT(&$$->vals);
		TAILQ_CONCAT(&$$->vals, $3, next);
		free($3);
	}
	| name PLEQ values
	{
		$$ = emalloc(sizeof(struct cfparam));
		$$->operator = 1;
		$$->key = $1;
		TAILQ_INIT(&$$->vals);
		TAILQ_CONCAT(&$$->vals, $3, next);
		free($3);
	}
	| error
	{
		$$ = emalloc(sizeof(struct cfparam));
		$$->operator = -1;
		$$->key = NULL;
		TAILQ_INIT(&$$->vals);
	}
	;

/*
 * A parameter has a fixed name.  A variable definition looks just like a
 * parameter except that the name is a variable.
 */
macro	: APPLY
	{
		$$ = create_token(CF_STR);
		$$->s = $1;
		$$->len = strlen($1);
		$$->expr = NULL;
		TAILQ_NEXT($$, next) = NULL;
	}
	;
name	: STR
	{
		$$ = create_token(CF_STR);
		$$->s = $1;
		$$->len = strlen($1);
		$$->expr = NULL;
		TAILQ_NEXT($$, next) = NULL;
	}
	| VAR
	{
		$$ = create_token(CF_VAR);
		$$->s = $1;
		$$->len = strlen($1);
		$$->expr = NULL;
		TAILQ_NEXT($$, next) = NULL;
	}
	;

values	: value
	{

		$$ = emalloc(sizeof(struct cfvalues));
		TAILQ_INIT($$);
		TAILQ_INSERT_TAIL($$, $1, next);
	}
	| values ',' value
	{
		$$ = $1;
		TAILQ_INSERT_TAIL($$, $3, next);
	}
	;

value	: tokens
	{
		$$ = emalloc(sizeof(struct cfvalue));
		TAILQ_INIT(&$$->tokens);
		TAILQ_CONCAT(&$$->tokens, $1, next);
		free($1);
		TAILQ_NEXT($$, next) = NULL;
	}
	;

/*
 * Strings may be passed in pieces, because of quoting and/or variable
 * interpolation.  Reassemble them into a single string.
 */
tokens	:
	{
		$$ = emalloc(sizeof(struct cftokens));
		TAILQ_INIT($$);
	}
	| tokens BEGIN_AR expr END_AR
	{
		struct cftoken *ct;
		$$ = $1;
		ct = create_token(CF_EXPR);
		ct->s = NULL;
		ct->len = 0;
		ct->expr = $3;
		TAILQ_INSERT_TAIL($$, ct, next);
	}
	| tokens STR
	{
		struct cftoken *ct;
		$$ = $1;
		ct = create_token(CF_STR);
		ct->s = $2;
		ct->len = strlen($2);
		ct->expr = NULL;
		TAILQ_INSERT_TAIL($$, ct, next);
	}
	| tokens VAR
	{
		struct cftoken *ct;
		$$ = $1;
		ct = create_token(CF_VAR);
		ct->s = $2;
		ct->len = strlen($2);
		ct->expr = NULL;
		TAILQ_INSERT_TAIL($$, ct, next);
	}
	;
expr	: NUMBER
	{
		$$ = emalloc(sizeof(struct cfexpr));
		$$->type = CF_NUM;
		$$->op = '\0';
		$$->left = NULL;
		$$->right = NULL;
		$$->val = $1;
	}
	| VAR
	{
		$$ = emalloc(sizeof(struct cfexpr));
		$$->type = CF_VAR;
		$$->op = '\0';
		$$->left = NULL;
		$$->right = NULL;
		$$->val = $1;
	}
	| VAR1
	{
		$$ = emalloc(sizeof(struct cfexpr));
		$$->type = CF_VAR;
		$$->op = '\0';
		$$->left = NULL;
		$$->right = NULL;
		$$->val = $1;
	}
	| expr '+' expr
	{
		$$ = emalloc(sizeof(struct cfexpr));
		$$->type = CF_EXPR;
		$$->op = '+';
		$$->left = $1;
		$$->right = $3;
		$$->val = NULL;
	}
	| expr '-' expr
	{
		$$ = emalloc(sizeof(struct cfexpr));
		$$->type = CF_EXPR;
		$$->op = '-';
		$$->left = $1;
		$$->right = $3;
		$$->val = NULL;
	}
	| expr '*' expr
	{
		$$ = emalloc(sizeof(struct cfexpr));
		$$->type = CF_EXPR;
		$$->op = '*';
		$$->left = $1;
		$$->right = $3;
		$$->val = NULL;
	}
	| expr '/' expr
	{
		$$ = emalloc(sizeof(struct cfexpr));
		$$->type = CF_EXPR;
		$$->op = '/';
		$$->left = $1;
		$$->right = $3;
		$$->val = NULL;
	}
	| expr '%' expr
	{
		$$ = emalloc(sizeof(struct cfexpr));
		$$->type = CF_EXPR;
		$$->op = '%';
		$$->left = $1;
		$$->right = $3;
		$$->val = NULL;
	}
	| '-' '(' expr ')'
	{
		$$ = emalloc(sizeof(struct cfexpr));
		$$->type = CF_EXPR;
		$$->op = '~';
		$$->left = $3;
		$$->right = NULL;
		$$->val = NULL;
	}
	| '(' expr ')'
	{
		$$ = $2;
	}
	;
%%

struct cfsections cfglobals = TAILQ_HEAD_INITIALIZER(cfglobals);
struct cfsections cftemplates = TAILQ_HEAD_INITIALIZER(cftemplates);
struct cfsections cfvms = TAILQ_HEAD_INITIALIZER(cfvms);

struct cfsection *
add_section(enum SECTION sec, char *name)
{
	static struct cfsections *sections[] = {
		&cfglobals, &cftemplates, &cfvms
	};
	static char *sec_names[] = {"global", "template", "vm"};
	struct cfsection *v;

	if (name != NULL && sec != SECTION_GLOBAL)
		TAILQ_FOREACH (v, sections[sec], next)
			if (strcmp(v->name, name) == 0) {
				ERR("%s: %s '%s' already exists.",
				    peek_filename(), sec_names[sec], name);
				v->duplicate++;
				break;
			}

	v = emalloc(sizeof(*v));
	memset(v, 0, sizeof(*v));
	v->name = name;
	v->owner = peek_fileowner();
	TAILQ_INIT(&v->params);
	TAILQ_INSERT_TAIL(sections[sec], v, next);
	return v;
}

/*
 * Exit slightly more gracefully when out of memory.
 */
void *
emalloc(size_t size)
{
	void *p;

	p = malloc(size);
	if (!p)
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
