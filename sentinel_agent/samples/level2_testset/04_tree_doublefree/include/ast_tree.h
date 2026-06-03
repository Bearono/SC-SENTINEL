#ifndef AST_TREE_H
#define AST_TREE_H

/*
 * Minimal AST (Abstract Syntax Tree) node allocator
 * CWE-415: Double Free
 * Inspired by: cJSON issue #833 (double free in cJSON_Delete)
 *              CVE pattern: shared child nodes freed via multiple parents
 *
 * Root cause:
 *   ast_node_free() is recursive and does not set freed child pointers
 *   to NULL.  When a node is referenced from two parents (e.g. after
 *   ast_node_move_child()), freeing both parents frees the shared child
 *   twice.  Also, ast_node_replace() can leave the old node pointer in
 *   the parent while also calling free on it, then the parent's
 *   destructor frees it again.
 */

#include <stddef.h>
#include <stdint.h>

/* Node types */
typedef enum {
    NODE_PROGRAM,
    NODE_FUNCTION,
    NODE_BLOCK,
    NODE_ASSIGN,
    NODE_BINOP,
    NODE_UNOP,
    NODE_CALL,
    NODE_IDENT,
    NODE_NUMBER,
    NODE_STRING,
    NODE_IF,
    NODE_WHILE,
    NODE_RETURN,
} node_type_t;

#define MAX_CHILDREN 16

typedef struct ast_node {
    node_type_t      type;
    char            *name;       /* identifier / operator string */
    double           number;     /* for NODE_NUMBER */

    struct ast_node *children[MAX_CHILDREN];
    int              child_count;

    struct ast_node *parent;     /* back-pointer (not owned) */
    int              ref_count;  /* UNUSED in buggy version */
} ast_node_t;

/* Allocator / builder */
ast_node_t *ast_node_new(node_type_t type, const char *name);
void        ast_node_free(ast_node_t *node);          /* VULNERABLE */
int         ast_node_add_child(ast_node_t *parent, ast_node_t *child);
ast_node_t *ast_node_detach_child(ast_node_t *parent, int index);
void        ast_node_replace(ast_node_t *parent, int index,
                             ast_node_t *new_child);  /* VULNERABLE */

/* Tree operations (build call graph for Agent B) */
ast_node_t *ast_parse_expr(const char *src, size_t len);
ast_node_t *ast_parse_stmt(const char *src, size_t len);
ast_node_t *ast_parse_program(const char *src, size_t len);
void        ast_print(const ast_node_t *node, int indent);
int         ast_node_count(const ast_node_t *node);

/* Serialization (for harness variety) */
int         ast_serialize(const ast_node_t *node, char *out, size_t max);
ast_node_t *ast_deserialize(const char *buf, size_t len);  /* entry for fuzz */

#endif /* AST_TREE_H */
