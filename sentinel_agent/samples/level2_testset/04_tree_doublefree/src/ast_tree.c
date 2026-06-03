/*
 * ast_tree.c — AST node manager with double-free vulnerability
 *
 * Vulnerability: CWE-415 Double Free
 * Inspired by:   cJSON issue #833 (cJSON_Delete doesn't NULL freed ptrs)
 * Location:      ast_node_free() / ast_node_replace()
 *
 * Root cause (two paths to double-free):
 *
 *  Path A — ast_node_replace():
 *    Calls ast_node_free(parent->children[index]) to drop the old child,
 *    but does NOT set parent->children[index] = NULL before assigning the
 *    new child.  If new_child == old_child (accidental aliasing) or if the
 *    parent is later freed with ast_node_free(), the old node is freed twice.
 *
 *  Path B — shared child after ast_node_add_child() to two parents:
 *    ast_node_add_child() does not copy the child node; it stores the same
 *    pointer in two parents.  Freeing parent A frees the child; freeing
 *    parent B frees the same child pointer again → double-free.
 *
 *  Path C — ast_node_free() does not NULL-terminate the children array
 *    after recursing, so if a partially-freed tree node is accessed again
 *    (e.g. via a live parent pointer after error recovery), stale child
 *    pointers are re-freed.
 */

#include "ast_tree.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ------------------------------------------------------------------ */
/* Allocator                                                            */
/* ------------------------------------------------------------------ */
ast_node_t *ast_node_new(node_type_t type, const char *name)
{
    ast_node_t *n = (ast_node_t *)calloc(1, sizeof(ast_node_t));
    if (!n) return NULL;
    n->type = type;
    if (name) {
        n->name = strdup(name);
        if (!n->name) { free(n); return NULL; }
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* VULNERABLE: ast_node_free                                            */
/*                                                                     */
/* Recursively frees children, but:                                    */
/*  1. Does not set children[i] = NULL after freeing — leaving stale  */
/*     pointers if the parent struct is re-examined.                   */
/*  2. Does not check ref_count, so shared nodes are freed multiple   */
/*     times.                                                          */
/* ------------------------------------------------------------------ */
void ast_node_free(ast_node_t *node)
{
    if (!node) return;

    for (int i = 0; i < node->child_count; i++) {
        /*
         * DOUBLE-FREE PATH B/C:
         * If children[i] has already been freed (e.g. shared node freed
         * via another parent, or freed by ast_node_replace), this call
         * triggers a double-free.
         *
         * The missing fix:
         *   ast_node_free(node->children[i]);
         *   node->children[i] = NULL;   <-- not done here
         */
        ast_node_free(node->children[i]);
        /* children[i] still holds the freed pointer — NOT zeroed */
    }

    free(node->name);
    free(node);   /* frees the struct; if called again → double-free */
}

/* ------------------------------------------------------------------ */
/* ast_node_add_child                                                   */
/* ------------------------------------------------------------------ */
int ast_node_add_child(ast_node_t *parent, ast_node_t *child)
{
    if (!parent || !child) return -1;
    if (parent->child_count >= MAX_CHILDREN) return -1;
    parent->children[parent->child_count++] = child;
    child->parent = parent;
    return 0;
}

/* ------------------------------------------------------------------ */
/* ast_node_detach_child                                                */
/* ------------------------------------------------------------------ */
ast_node_t *ast_node_detach_child(ast_node_t *parent, int index)
{
    if (!parent || index < 0 || index >= parent->child_count) return NULL;
    ast_node_t *child = parent->children[index];
    /* Shift remaining children */
    for (int i = index; i < parent->child_count - 1; i++)
        parent->children[i] = parent->children[i + 1];
    parent->children[--parent->child_count] = NULL;
    if (child) child->parent = NULL;
    return child;
}

/* ------------------------------------------------------------------ */
/* VULNERABLE: ast_node_replace                                         */
/*                                                                     */
/* Frees old child but does not set slot to NULL before assignment.    */
/* If new_child == old_child (or if error recovery re-frees parent),  */
/* old_child is freed twice.                                           */
/* ------------------------------------------------------------------ */
void ast_node_replace(ast_node_t *parent, int index,
                      ast_node_t *new_child)
{
    if (!parent || index < 0 || index >= parent->child_count) return;

    ast_node_t *old = parent->children[index];

    /*
     * DOUBLE-FREE PATH A:
     * ast_node_free(old) frees the old child.
     * parent->children[index] is NOT set to NULL here.
     * If new_child == old, the very next line re-assigns the freed ptr.
     * When the parent is later freed, ast_node_free() will be called
     * on parent->children[index] again → double-free on 'old'.
     *
     * Also: if caller passes new_child == old (no-op intent), old is
     * freed immediately and then re-stored as a live pointer → UAF + DF.
     */
    ast_node_free(old);                          /* free old */
    parent->children[index] = new_child;         /* BUG: old may == new */
    if (new_child) new_child->parent = parent;
}

/* ------------------------------------------------------------------ */
/* Simple recursive descent parser for fuzzing surface                 */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *src;
    size_t      pos;
    size_t      len;
} parse_ctx_t;

static void skip_ws(parse_ctx_t *p)
{
    while (p->pos < p->len && isspace((unsigned char)p->src[p->pos]))
        p->pos++;
}

static int peek_char(parse_ctx_t *p)
{
    if (p->pos >= p->len) return -1;
    return (unsigned char)p->src[p->pos];
}

/* Parse a decimal number literal */
static ast_node_t *parse_number(parse_ctx_t *p)
{
    skip_ws(p);
    if (!isdigit(peek_char(p)) && peek_char(p) != '-') return NULL;
    size_t start = p->pos;
    if (peek_char(p) == '-') p->pos++;
    while (p->pos < p->len && isdigit((unsigned char)p->src[p->pos]))
        p->pos++;
    if (p->pos < p->len && p->src[p->pos] == '.')
        while (p->pos < p->len && isdigit((unsigned char)p->src[++p->pos])) {}

    char tmp[64] = {0};
    size_t l = p->pos - start;
    if (l >= sizeof(tmp)) l = sizeof(tmp) - 1;
    memcpy(tmp, p->src + start, l);

    ast_node_t *n = ast_node_new(NODE_NUMBER, tmp);
    if (n) n->number = atof(tmp);
    return n;
}

/* Parse an identifier */
static ast_node_t *parse_ident(parse_ctx_t *p)
{
    skip_ws(p);
    int c = peek_char(p);
    if (!isalpha(c) && c != '_') return NULL;
    size_t start = p->pos;
    while (p->pos < p->len &&
           (isalnum((unsigned char)p->src[p->pos]) || p->src[p->pos] == '_'))
        p->pos++;
    char tmp[128] = {0};
    size_t l = p->pos - start;
    if (l >= sizeof(tmp)) l = sizeof(tmp) - 1;
    memcpy(tmp, p->src + start, l);
    return ast_node_new(NODE_IDENT, tmp);
}

/* Parse expr: number | ident | ident '(' args ')' | expr op expr */
static ast_node_t *parse_expr_inner(parse_ctx_t *p, int depth)
{
    if (depth > 16) return NULL;
    skip_ws(p);
    int c = peek_char(p);

    ast_node_t *lhs = NULL;

    if (isdigit(c) || c == '-') {
        lhs = parse_number(p);
    } else if (isalpha(c) || c == '_') {
        lhs = parse_ident(p);
        skip_ws(p);
        if (lhs && peek_char(p) == '(') {
            /* Function call */
            p->pos++;
            ast_node_t *call = ast_node_new(NODE_CALL, lhs->name);
            ast_node_free(lhs); lhs = NULL;
            if (!call) return NULL;
            while (p->pos < p->len && peek_char(p) != ')') {
                skip_ws(p);
                if (peek_char(p) == ',') { p->pos++; continue; }
                ast_node_t *arg = parse_expr_inner(p, depth + 1);
                if (arg) ast_node_add_child(call, arg);
                else break;
            }
            if (peek_char(p) == ')') p->pos++;
            lhs = call;
        }
    } else if (c == '(') {
        p->pos++;
        lhs = parse_expr_inner(p, depth + 1);
        skip_ws(p);
        if (peek_char(p) == ')') p->pos++;
    }

    if (!lhs) return NULL;

    /* Binary operator */
    skip_ws(p);
    c = peek_char(p);
    if (c == '+' || c == '-' || c == '*' || c == '/' || c == '%') {
        char op[2] = { (char)c, '\0' };
        p->pos++;
        ast_node_t *rhs = parse_expr_inner(p, depth + 1);
        if (rhs) {
            ast_node_t *binop = ast_node_new(NODE_BINOP, op);
            if (binop) {
                ast_node_add_child(binop, lhs);
                ast_node_add_child(binop, rhs);
                return binop;
            }
            ast_node_free(rhs);
        }
    }
    return lhs;
}

ast_node_t *ast_parse_expr(const char *src, size_t len)
{
    parse_ctx_t p = { src, 0, len };
    return parse_expr_inner(&p, 0);
}

/* Parse assign: ident '=' expr ';' */
ast_node_t *ast_parse_stmt(const char *src, size_t len)
{
    parse_ctx_t p = { src, 0, len };
    skip_ws(&p);

    ast_node_t *id = parse_ident(&p);
    if (!id) return NULL;

    skip_ws(&p);
    if (peek_char(&p) != '=') {
        ast_node_free(id);
        return NULL;
    }
    p.pos++;

    ast_node_t *expr = parse_expr_inner(&p, 0);
    if (!expr) { ast_node_free(id); return NULL; }

    ast_node_t *assign = ast_node_new(NODE_ASSIGN, "=");
    if (!assign) { ast_node_free(id); ast_node_free(expr); return NULL; }
    ast_node_add_child(assign, id);
    ast_node_add_child(assign, expr);
    return assign;
}

/* Parse program: sequence of statements */
ast_node_t *ast_parse_program(const char *src, size_t len)
{
    ast_node_t *prog = ast_node_new(NODE_PROGRAM, "program");
    if (!prog) return NULL;
    size_t offset = 0;
    while (offset < len) {
        size_t rem = len - offset;
        ast_node_t *stmt = ast_parse_stmt(src + offset, rem);
        if (!stmt) { offset++; continue; }
        ast_node_add_child(prog, stmt);
        offset += 2; /* simplified advance */
    }
    return prog;
}

void ast_print(const ast_node_t *node, int indent)
{
    if (!node) return;
    for (int i = 0; i < indent; i++) putchar(' ');
    printf("[%d] %s\n", node->type, node->name ? node->name : "(null)");
    for (int i = 0; i < node->child_count; i++)
        ast_print(node->children[i], indent + 2);
}

int ast_node_count(const ast_node_t *node)
{
    if (!node) return 0;
    int cnt = 1;
    for (int i = 0; i < node->child_count; i++)
        cnt += ast_node_count(node->children[i]);
    return cnt;
}

/* ------------------------------------------------------------------ */
/* Serialization / deserialization (fuzz entry point)                  */
/*                                                                     */
/* Format: TYPE:NAME;CHILD_COUNT[children...]                          */
/* ast_deserialize is the primary fuzzing surface.                     */
/* ------------------------------------------------------------------ */
int ast_serialize(const ast_node_t *node, char *out, size_t max)
{
    if (!node || !out || max == 0) return -1;
    int w = snprintf(out, max, "%d:%s;%d",
                     (int)node->type,
                     node->name ? node->name : "",
                     node->child_count);
    if (w < 0 || (size_t)w >= max) return -1;
    for (int i = 0; i < node->child_count; i++) {
        w += ast_serialize(node->children[i], out + w, max - (size_t)w);
    }
    return w;
}

ast_node_t *ast_deserialize(const char *buf, size_t len)
{
    if (!buf || len < 3) return NULL;
    int  type_int   = 0;
    int  child_cnt  = 0;
    char name[64]   = {0};

    int consumed = sscanf(buf, "%d:%63[^;];%d", &type_int, name, &child_cnt);
    if (consumed < 2) return NULL;

    if (type_int < 0 || type_int > (int)NODE_RETURN) return NULL;

    ast_node_t *node = ast_node_new((node_type_t)type_int, name[0] ? name : NULL);
    if (!node) return NULL;

    /* Advance past header (rough: find second ';') */
    const char *p = buf;
    int scount = 0;
    while ((size_t)(p - buf) < len && scount < 2) {
        if (*p == ';') scount++;
        p++;
    }

    /* Parse children from remainder of buffer */
    if (child_cnt < 0) child_cnt = 0;
    if (child_cnt > MAX_CHILDREN) child_cnt = MAX_CHILDREN;

    for (int i = 0; i < child_cnt && (size_t)(p - buf) < len; i++) {
        size_t rem = len - (size_t)(p - buf);
        ast_node_t *child = ast_deserialize(p, rem);
        if (!child) break;

        /*
         * DOUBLE-FREE SETUP (Path B):
         * On a crafted input where the same substring appears twice,
         * ast_deserialize may create two parent nodes that both call
         * ast_node_add_child with the SAME child pointer.
         * (Here it is possible if fuzz input causes reuse of 'child'
         *  across loop iterations due to the simplistic pointer advance.)
         */
        ast_node_add_child(node, child);

        /* Advance p by a fixed step — intentionally imprecise */
        p += (rem > 4) ? 4 : rem;
    }

    return node;
}
