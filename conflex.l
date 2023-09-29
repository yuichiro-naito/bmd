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

#include <err.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "confparse.h"
#include "y.tab.h"

extern int yynerrs;

static ssize_t text2lval(size_t triml, size_t trimr, int tovar);

int lineno = 1;

#define YY_DECL int yylex(void)
%}

%option noinput
%option nounput
%option stack

%start _ DQ AR PR

%%

			/* Whitespace or equivalent */
<_,AR,PR>[ \t]+		;
<_>#.*			;
<_>\/\/.*		;
<_,DQ>\$\(\(		{
				yy_push_state(AR);
				return BEGIN_AR;
			}
<AR,PR>0x[0-9a-fA-F]+	{
				(void)text2lval(0, 0, 0);
				return NUMBER;
			}
<AR,PR>0[0-7]+		{
				(void)text2lval(0, 0, 0);
				return NUMBER;
			}
<AR,PR>[0-9][0-9]*		{
				(void)text2lval(0, 0, 0);
				return NUMBER;
			}
<AR,PR>[\+\-\*\/%]	{
				return yytext[0];
			}
<AR,PR>\(		{
				yy_push_state(PR);
				return yytext[0];
			}
<PR>\)			{
				yy_pop_state();
				return yytext[0];
			}
<AR>\)\)		{
				yy_pop_state();
				return END_AR;
			}
<_>\/\*([^*]|(\*+([^*\/])))*\*+\/ {
				const char *s;

				for (s = yytext; s < yytext + yyleng; s++)
					if (*s == '\n')
						lineno++;
			}
<_>\n			{
				lineno++;
			}

			/* Reserved tokens */
<_>global		{
				return GLOBAL;
			}
<_>vm			{
				return VM;
			}
<_>template		{
				return TEMPLATE;
			}
<_>.include		{
				return INCLUDE;
			}
<_>.apply		{
				(void)text2lval(0, 0, 0);
				return APPLY;
			}
<_>\+=			{
				return PLEQ;
			}
<_>[,;={}]		{
				return yytext[0];
			}

			/* Atomic (unquoted) strings */
<_,DQ>[A-Za-z0-9_!%&()\-.:<>?@\[\]^`|~]+ |
<_,DQ>\\(.|\n|[0-7]{1,3}|x[0-9A-Fa-f]{1,2}) |
<_,DQ>[$*+/\\]		{
				(void)text2lval(0, 0, 0);
				return STR;
			}

			/* Single and double quoted strings */
<_>'([^\'\\]|\\(.|\n))*' {
				(void)text2lval(1, 1, 0);
				return STR;
			}
<_>\"([^"\\]|\\(.|\n))*\" |
<DQ>[^\"$\\]([^"\\]|\\(.|\n))*\" {
				size_t skip;
				ssize_t atvar;

				skip = yytext[0] == '"' ? 1 : 0;
				atvar = text2lval(skip, 1, 1);
				if (atvar < 0)
					BEGIN _;
				else {
					/*
					 * The string has a variable inside it.
					 * Go into DQ mode to get the variable
					 * and then the rest of the string.
					 */
					BEGIN DQ;
					yyless(atvar);
				}
				return STR;
			}
<DQ>\"			BEGIN _;

			/* Variables, single-word or bracketed */
<_,DQ,AR,PR>$[A-Za-z_][A-Za-z_0-9]* {
				(void)text2lval(1, 0, 0);
				return VAR;
			}
<_,AR,PR>$\{([^\n{}]|\\(.|\n))*\} |
<DQ>$\{([^\n\"{}]|\\(.|\n))*\} {
				(void)text2lval(2, 1, 0);
				return VAR;
			}

			/* Partially formed bits worth complaining about */
<_>\/\*([^*]|(\*+([^*\/])))*\** {
				ERR("%s line %d: unterminated comment",
				      peek_filename(), lineno);
				yynerrs++;
			}
<_>'([^\n'\\]|\\.)*	|
<_>\"([^\n\"\\]|\\.)*	{
				ERR("%s line %d: unterminated string",
				      peek_filename(), lineno);
				yynerrs++;
			}
<_>$\{([^\n{}]|\\.)*	|
<DQ>$\{([^\n\"{}]|\\.)*	{
				ERR("%s line %d: unterminated variable",
				      peek_filename(), lineno);
				yynerrs++;
			}

			/* A hack because "<0>" rules aren't allowed */
<_>.			return yytext[0];
.|\n			{
				BEGIN _;
				yyless(0);
			}

%%

void
yyerror(const char *s)
{
	char *fn = peek_filename();

	if (!yytext)
		ERR("%s line %d: %s\n", fn, lineno, s);
	else if (!yytext[0])
		ERR("%s: unexpected EOF", fn);
	else
		ERR("%s line %d: '%s': %s", fn, lineno, yytext, s);
}

/*
 * Copy string from yytext to yylval, handling backslash escapes,
 * and optionally stopping at the beginning of a variable.
 */
static ssize_t
text2lval(size_t triml, size_t trimr, int tovar)
{
	char *d;
	const char *s, *se;

	yylval.cs = d = emalloc(yyleng - trimr - triml + 1);
	if (d == NULL)
		return 0;
	se = yytext + (yyleng - trimr);
	for (s = yytext + triml; s < se; s++, d++) {
		if (*s != '\\') {
			if (tovar && *s == '$') {
				*d = '\0';
				return s - yytext;
			}
			if (*s == '\n')
				lineno++;
			*d = *s;
			continue;
		}
		s++;
		if (*s >= '0' && *s <= '7') {
			*d = *s - '0';
			if (s + 1 < se && s[1] >= '0' && s[1] <= '7') {
				*d = 010 * *d + (*++s - '0');
				if (s + 1 < se && s[1] >= '0' && s[1] <= '7')
					*d = 010 * *d + (*++s - '0');
			}
			continue;
		}
		switch (*s) {
		case 'a':	*d = '\a';	break;
		case 'b':	*d = '\b';	break;
		case 'f':	*d = '\f';	break;
		case 'n':	*d = '\n';	break;
		case 'r':	*d = '\r';	break;
		case 't':	*d = '\t';	break;
		case 'v':	*d = '\v';	break;
		case '\n':	d--; lineno++;	break;
		default:	*d = *s;	break;
		case 'x':
			*d = 0;
			if (s + 1 >= se)
				break;
			if (s[1] >= '0' && s[1] <= '9')
				*d = *++s - '0';
			else if (s[1] >= 'A' && s[1] <= 'F')
				*d = *++s + (0xA - 'A');
			else if (s[1] >= 'a' && s[1] <= 'f')
				*d = *++s + (0xa - 'a');
			else
				break;
			if (s + 1 >= se)
				break;
			if (s[1] >= '0' && s[1] <= '9')
				*d = *d * 0x10 + (*++s - '0');
			else if (s[1] >= 'A' && s[1] <= 'F')
				*d = *d * 0x10 + (*++s + (0xA - 'A'));
			else if (s[1] >= 'a' && s[1] <= 'f')
				*d = *d * 0x10 + (*++s + (0xa - 'a'));
		}
	}
	*d = '\0';
	return -1;
}
