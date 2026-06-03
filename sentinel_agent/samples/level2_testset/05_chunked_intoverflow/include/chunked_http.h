#ifndef CHUNKED_HTTP_H
#define CHUNKED_HTTP_H

/*
 * Minimal HTTP chunked-transfer decoder
 * CWE-190: Integer Overflow → CWE-122 Heap Buffer Overflow
 * Inspired by: CVE-2017-8798 (miniupnpc integer signedness error)
 *
 * Root cause:
 *   get_chunk_size() parses the chunk-size hex field and returns it as
 *   a signed int.  A large hex value (e.g. 0x80000000) produces a
 *   negative signed integer.  When this value is passed to realloc()
 *   after being cast to size_t, it wraps around to a huge positive
 *   value, causing either an OOM abort or — on 32-bit / with small
 *   address space — an under-sized allocation that is then written past.
 *
 *   In the secondary bug, the caller does:
 *       content_buf = realloc(content_buf, content_length + chunk_size);
 *   where content_length is size_t but chunk_size is signed int.
 *   The mixed-sign arithmetic produces content_length + negative_chunk,
 *   yielding a very small (or zero) realloc size, followed by a full
 *   chunk_size memcpy that overflows the tiny buffer.
 */

#include <stddef.h>
#include <stdint.h>

#define HTTP_MAX_RESPONSE  (4 * 1024 * 1024)  /* 4 MB safety cap */
#define CHUNK_LINE_MAX     32

/* Parsed HTTP response state */
typedef struct {
    int      status_code;
    char     content_type[64];
    int      content_length;    /* from Content-Length header, -1 if absent */
    int      chunked;           /* Transfer-Encoding: chunked */

    uint8_t *body;              /* assembled body (heap) */
    size_t   body_len;

    char     error[128];
} http_response_t;

/* Public API */
http_response_t *http_response_new(void);
void             http_response_free(http_response_t *r);

int  http_parse_headers(http_response_t *r,
                        const uint8_t *data, size_t len,
                        size_t *header_end);
int  http_decode_chunked(http_response_t *r,
                         const uint8_t *data, size_t len);   /* VULNERABLE */
int  http_parse_response(http_response_t *r,
                         const uint8_t *data, size_t len);

/* Internal */
int  get_chunk_size(const char *line, size_t len);            /* returns signed int — BUG */
int  http_append_body(http_response_t *r,
                      const uint8_t *data, size_t len);

#endif /* CHUNKED_HTTP_H */
