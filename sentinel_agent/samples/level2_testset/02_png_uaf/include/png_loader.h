#ifndef PNG_LOADER_H
#define PNG_LOADER_H

/*
 * Minimal PNG-like chunk loader
 * CWE-416: Use-After-Free
 * Inspired by CVE-2019-7317 (libpng < 1.6.37)
 *
 * Root cause: png_image_cleanup() is registered as a setjmp-based
 * cleanup callback that holds a pointer to the image struct.
 * If the image is stack-allocated and the caller frees/reuses the
 * stack frame before the error-path cleanup fires, the callback
 * dereferences a dangling pointer.
 *
 * Here we model this with a callback registry: a chunk post-processor
 * callback captures a pointer to a temporary ChunkCtx, which gets
 * freed when processing moves to the next chunk, leaving the callback
 * pointing to freed memory.
 */

#include <stddef.h>
#include <stdint.h>

#define PNG_SIG_LEN      8
#define MAX_CHUNK_DATA   (1 << 16)   /* 64 KB */
#define MAX_CALLBACKS    16

/* Chunk types (4-byte ASCII, stored as uint32) */
#define CHUNK_IHDR  0x49484452U   /* "IHDR" */
#define CHUNK_IDAT  0x49444154U   /* "IDAT" */
#define CHUNK_IEND  0x49454E44U   /* "IEND" */
#define CHUNK_tEXt  0x74455874U   /* "tEXt" */
#define CHUNK_zTXt  0x7A545874U   /* "zTXt" */
#define CHUNK_PLTE  0x504C5445U   /* "PLTE" */

/* Image info decoded from IHDR */
typedef struct {
    uint32_t width;
    uint32_t height;
    uint8_t  bit_depth;
    uint8_t  color_type;
    uint8_t  compression;
    uint8_t  filter;
    uint8_t  interlace;
} png_ihdr_t;

/* Per-chunk processing context (stack-allocated in process_chunk) */
typedef struct {
    uint32_t  type;
    uint8_t  *data;     /* malloc'd  */
    uint32_t  length;
    uint32_t  crc;
    int       valid;
} chunk_ctx_t;

/* Post-process callback type */
typedef void (*chunk_callback_t)(const chunk_ctx_t *ctx, void *userdata);

/* Top-level image handle */
typedef struct {
    png_ihdr_t           ihdr;
    int                  ihdr_seen;

    /* Callback registry — stores raw pointers (UAF source) */
    chunk_callback_t     callbacks[MAX_CALLBACKS];
    void                *cb_userdata[MAX_CALLBACKS];
    const chunk_ctx_t   *cb_ctx[MAX_CALLBACKS];   /* DANGLING after chunk freed */
    int                  cb_count;

    uint8_t             *pixels;    /* decoded pixel data (simplified) */
    size_t               pixel_len;

    char                 error[128];
} png_image_t;

/* Public API */
png_image_t *png_image_create(void);
void         png_image_free(png_image_t *img);        /* may trigger UAF */
int          png_load(png_image_t *img,
                      const uint8_t *data, size_t len);
void         png_register_callback(png_image_t *img,
                                   chunk_callback_t cb, void *userdata);

/* Internal — exposed for Agent C / harness */
int  png_check_signature(const uint8_t *data, size_t len);
int  png_process_chunk(png_image_t *img,
                       const uint8_t *data, size_t len, size_t *consumed);
void png_fire_callbacks(png_image_t *img);   /* VULNERABLE: fires on freed ctx */
int  png_decode_ihdr(png_image_t *img, const uint8_t *data, uint32_t len);

#endif /* PNG_LOADER_H */
