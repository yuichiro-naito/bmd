#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>

#include "parser.h"

typedef enum {
	NUMBER,
	OPERATOR
} TYPE;

struct arith_token {
	SLIST_ENTRY(arith_token) next;
	TYPE type;
	int prio;
	int value;
};

#define IS_OPERATOR(tk, v)  ((tk)->type == OPERATOR && (tk)->value == (v))
#define IS_NUMBER(tk)       ((tk)->type == NUMBER)

SLIST_HEAD(arith_list, arith_token);

static struct arith_token *
new_value(int val)
{
	struct arith_token *token;
	if ((token = malloc(sizeof(*token))) == NULL)
		return NULL;
	token->type = NUMBER;
	token->value = val;
	token->prio = 0;
	return token;
}

static struct arith_token *
new_operator(int op)
{
	struct arith_token *token;
	if ((token = malloc(sizeof(*token))) == NULL)
		return NULL;
	token->type = OPERATOR;
	token->value = op;
	switch (op) {
	default:
		token->prio = 0;
		break;
	case '*':
	case '/':
	case '%':
		token->prio = 1;
		break;
	case '+':
	case '-':
		token->prio = 2;
		break;
	case '(':
	case ')':
		token->prio = 3;
		break;
	}
	return token;
}

static struct arith_token *
get_token(FILE *fp, struct vm_conf *conf)
{
	int c, f;
	long num = 0;

	f = 0;
	while ((c = getc_unlocked(fp)) != EOF) {
		switch(c) {
		case '$':
			if (parse_variable(fp, conf, NULL, &num) > 0)
				return new_value(num);
			break;
		case ' ':
		case '\t':
		case '\n':
			continue;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			num = num * 10 + c - '0';
			f = 1;
			break;
		case '-':
		case '+':
		case '*':
		case '/':
		case '%':
		case '(':
		case ')':
			if ( f ) {
				ungetc(c, fp);
				return new_value(num);
			}
			return new_operator(c);
		default:
			break;
		}
	}

	if ( f )
		return new_value(num);
	return NULL;
}

static int
parse(FILE *fp, struct vm_conf *conf, struct arith_list *rpn)
{
	struct arith_list p, s;
	struct arith_token *tk, *pt, *pn, *st;
	int first = 1;
	int minus = 0;

	SLIST_INIT(&s);
	SLIST_INIT(&p);

	while ((tk = get_token(fp, conf)) != NULL) {
		if (first) {
			first = 0;
			if (IS_OPERATOR(tk, '-')) {
				minus = 1;
				free(tk);
				continue;
			}
		}
		if (IS_OPERATOR(tk, '(')) {
			SLIST_INSERT_HEAD(&s, tk, next);
			first = 1;
			continue;
		}
		if (IS_OPERATOR(tk, ')')) {
			while ((st = SLIST_FIRST(&s)) != NULL) {
				SLIST_REMOVE_HEAD(&s, next);
				if (IS_OPERATOR(st, '(')) {
					free(st);
					break;
				}
				SLIST_INSERT_HEAD(&p, st, next);
			}
			free(tk);
			continue;
		}

		while ((st = SLIST_FIRST(&s)) != NULL) {
			if (tk->prio < st->prio)
				break;
			SLIST_REMOVE_HEAD(&s, next);
			SLIST_INSERT_HEAD(&p, st, next);
		}
		if (IS_NUMBER(tk) && minus) {
			minus = 0;
			tk->value = - tk->value;
		}
		SLIST_INSERT_HEAD(&s, tk, next);
	}

	SLIST_FOREACH_SAFE(pt, &p, next, pn)
		SLIST_INSERT_HEAD(&s, pt, next);

	*rpn = s;
	return 0;
}

static int
calc(struct arith_list *rpn, int *ret)
{
	struct arith_token *a, *b, *tk;
	struct arith_list stack;

	SLIST_INIT(&stack);

	while ((tk = SLIST_FIRST(rpn)) != NULL) {
		SLIST_REMOVE_HEAD(rpn, next);
		switch(tk->type) {
		case NUMBER:
			SLIST_INSERT_HEAD(&stack, tk, next);
			break;
		case OPERATOR:
			if ((b = SLIST_FIRST(&stack)) == NULL)
				goto err;
			SLIST_REMOVE_HEAD(&stack, next);
			if ((a = SLIST_FIRST(&stack)) == NULL) {
				free(b);
				goto err;
			}
			SLIST_REMOVE_HEAD(&stack, next);
			switch (tk->value) {
			case '+':
				a->value = a->value + b->value;
				break;
			case '-':
				a->value = a->value - b->value;
				break;
			case '*':
				a->value = a->value * b->value;
				break;
			case '/':
				a->value = a->value / b->value;
				break;
			case '%':
				a->value = a->value % b->value;
				break;
			}
			free(b);
			free(tk);
			SLIST_INSERT_HEAD(&stack, a, next);
			break;
		}
	}

	a = SLIST_FIRST(&stack);
	if (a == NULL)
		return -1;
	SLIST_REMOVE_HEAD(&stack, next);
	*ret = a->value;
	free(a);
	return 0;

err:
	SLIST_FOREACH_SAFE(a, &stack, next, b)
		free(a);
	SLIST_FOREACH_SAFE(a, rpn, next, b)
		free(a);
	SLIST_INIT(rpn);
	return -1;
}

int
reverse_polish_notation(FILE *fp, struct vm_conf *conf, int *val)
{
	struct arith_list rpn;

	if (parse(fp, conf, &rpn) < 0)
		return -1;
	return calc(&rpn, val);
}
