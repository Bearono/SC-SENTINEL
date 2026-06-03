#ifndef JSON_PARSER_H
#define JSON_PARSER_H

/*
 * Minimal JSON parser - CVE-2019-11834 inspired
 * Heap buffer overflow in parse_string() via \x00 handling
 * CWE-122: Heap-based Buffer Overflow
 */

#include <stddef.h>
#include <stdint.h>

#define JSON_MAX_DEPTH   32
#define JSON_STRING_INIT 64

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT,
    JSON_ERROR
} json_type_t;

typedef struct json_value {
    json_type_t          type;
    char                *key;
    union {
        double               number;
        int                  boolean;
        char                *string;
        struct json_value   *children;  /* array / object */
    } v;
    struct json_value   *next;          /* sibling */
} json_value_t;

typedef struct {
    const char  *src;
    size_t       pos;
    size_t       len;
    int          depth;
    char        *error;
} json_ctx_t;

/* Public API */
json_value_t *json_parse(const char *input, size_t len);
void          json_free(json_value_t *val);
const char   *json_get_string(const json_value_t *val, const char *key);
double        json_get_number(const json_value_t *val, const char *key);
void          json_print(const json_value_t *val, int indent);

/* Internal - exposed for fuzzing harness */
json_value_t *json_parse_value(json_ctx_t *ctx);
char         *json_parse_string(json_ctx_t *ctx);   /* VULNERABLE */
json_value_t *json_parse_array(json_ctx_t *ctx);
json_value_t *json_parse_object(json_ctx_t *ctx);

#endif /* JSON_PARSER_H */
