/*
 * png_loader.c - Minimal PNG chunk processor with UAF vulnerability
 *
 * Vulnerability: CWE-416 Use-After-Free
 * Inspired by:   CVE-2019-7317 (libpng png_image_free UAF)
 * Location:      png_fire_callbacks() / png_process_chunk()
 *
 * Root cause:
 *   png_process_chunk() allocates a chunk_ctx_t on the heap, registers
 *   its address into img->cb_ctx[], processes the chunk, then frees the
 *   chunk data (and in the IEND path, the ctx itself).
 *
 *   png_fire_callbacks() is designed to be called after all chunks are
 *   processed (e.g. from png_image_free or an error handler).  It
 *   iterates img->cb_ctx[] and passes each stored pointer to the
 *   registered callback.  Because the ctx was freed at end of
 *   png_process_chunk(), the callback receives a dangling pointer →
 *   heap-use-after-free on the read inside the callback body.
 */

#include "png_loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PNG signature: 8 bytes */
static const uint8_t PNG_SIG[PNG_SIG_LEN] = {
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
};

/* ------------------------------------------------------------------ */
/* CRC-32 (simplified, no table) — for structural realism             */
/* ------------------------------------------------------------------ */
static uint32_t crc32_byte(uint32_t crc, uint8_t b)
{
    crc ^= b;
    for (int i = 0; i < 8; i++)
        crc = (crc >> 1) ^ (crc & 1 ? 0xEDB88320U : 0);
    return crc;
}

static uint32_t crc32_buf(const uint8_t *buf, size_t len)
{
    uint32_t crc = 0xFFFFFFFFU;
    for (size_t i = 0; i < len; i++)
        crc = crc32_byte(crc, buf[i]);
    return crc ^ 0xFFFFFFFFU;
}

/* ------------------------------------------------------------------ */
/* Read big-endian uint32                                              */
/* ------------------------------------------------------------------ */
static uint32_t read_u32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

/* ------------------------------------------------------------------ */
/* Public: create / free image handle                                  */
/* ------------------------------------------------------------------ */
png_image_t *png_image_create(void)
{
    png_image_t *img = (png_image_t *)calloc(1, sizeof(png_image_t));
    return img;
}

/*
 * png_image_free:
 *   Fires all registered callbacks BEFORE releasing the image.
 *   Because cb_ctx[] may hold pointers to already-freed chunk_ctx_t
 *   objects, this is the trigger site for the UAF.
 */
void png_image_free(png_image_t *img)
{
    if (!img) return;
    png_fire_callbacks(img);   /* <<< UAF trigger */
    free(img->pixels);
    free(img);
}

/* ------------------------------------------------------------------ */
/* png_register_callback                                               */
/* ------------------------------------------------------------------ */
void png_register_callback(png_image_t *img,
                            chunk_callback_t cb, void *userdata)
{
    if (!img || img->cb_count >= MAX_CALLBACKS) return;
    img->callbacks[img->cb_count]  = cb;
    img->cb_userdata[img->cb_count] = userdata;
    /* cb_ctx will be filled in by png_process_chunk */
    img->cb_ctx[img->cb_count] = NULL;
    img->cb_count++;
}

/* ------------------------------------------------------------------ */
/* png_check_signature                                                  */
/* ------------------------------------------------------------------ */
int png_check_signature(const uint8_t *data, size_t len)
{
    if (len < PNG_SIG_LEN) return 0;
    return memcmp(data, PNG_SIG, PNG_SIG_LEN) == 0;
}

/* ------------------------------------------------------------------ */
/* png_decode_ihdr                                                      */
/* ------------------------------------------------------------------ */
int png_decode_ihdr(png_image_t *img, const uint8_t *data, uint32_t len)
{
    if (len < 13) return -1;
    img->ihdr.width       = read_u32be(data + 0);
    img->ihdr.height      = read_u32be(data + 4);
    img->ihdr.bit_depth   = data[8];
    img->ihdr.color_type  = data[9];
    img->ihdr.compression = data[10];
    img->ihdr.filter      = data[11];
    img->ihdr.interlace   = data[12];
    img->ihdr_seen = 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* VULNERABLE: png_fire_callbacks                                       */
/*                                                                     */
/* Iterates cb_ctx[] — these pointers were stored during chunk         */
/* processing and may point to freed memory.                           */
/* ------------------------------------------------------------------ */
void png_fire_callbacks(png_image_t *img)
{
    for (int i = 0; i < img->cb_count; i++) {
        if (img->callbacks[i] && img->cb_ctx[i]) {
            /*
             * USE-AFTER-FREE: img->cb_ctx[i] was freed at the end of
             * png_process_chunk() when the chunk was "finalized".
             * Reading cb_ctx[i]->type here accesses freed heap memory.
             */
            img->callbacks[i](img->cb_ctx[i], img->cb_userdata[i]);
        }
    }
}

/* ------------------------------------------------------------------ */
/* png_process_chunk                                                    */
/*                                                                     */
/* Parses one chunk from data[offset..], updates *consumed.            */
/* The chunk_ctx_t is heap-allocated, a pointer is saved into          */
/* cb_ctx[], and then the ctx is freed — leaving a dangling pointer.   */
/* ------------------------------------------------------------------ */
int png_process_chunk(png_image_t *img,
                      const uint8_t *data, size_t len, size_t *consumed)
{
    *consumed = 0;
    if (len < 12) return -1;  /* need length(4) + type(4) + crc(4) */

    uint32_t chunk_len  = read_u32be(data + 0);
    uint32_t chunk_type = read_u32be(data + 4);

    if (chunk_len > MAX_CHUNK_DATA) {
        snprintf(img->error, sizeof(img->error),
                 "Chunk too large: %u", chunk_len);
        return -1;
    }
    if (8 + chunk_len + 4 > len) return -1;  /* truncated */

    const uint8_t *chunk_data = data + 8;
    uint32_t       stored_crc = read_u32be(data + 8 + chunk_len);

    /* Verify CRC (type bytes + data bytes) */
    uint32_t calc_crc = crc32_buf(data + 4, 4 + chunk_len);
    (void)stored_crc; (void)calc_crc;  /* skip strict CRC for fuzzing */

    /* Allocate chunk context */
    chunk_ctx_t *ctx = (chunk_ctx_t *)malloc(sizeof(chunk_ctx_t));
    if (!ctx) return -1;
    ctx->type   = chunk_type;
    ctx->length = chunk_len;
    ctx->crc    = stored_crc;
    ctx->valid  = 1;
    ctx->data   = NULL;

    if (chunk_len > 0) {
        ctx->data = (uint8_t *)malloc(chunk_len);
        if (!ctx->data) { free(ctx); return -1; }
        memcpy(ctx->data, chunk_data, chunk_len);
    }

    /* Dispatch on chunk type */
    switch (chunk_type) {
    case CHUNK_IHDR:
        png_decode_ihdr(img, chunk_data, chunk_len);
        break;
    case CHUNK_IDAT:
        /* Simplified: just accumulate pixel bytes */
        if (img->ihdr_seen && chunk_len > 0) {
            uint8_t *tmp = realloc(img->pixels,
                                   img->pixel_len + chunk_len);
            if (tmp) {
                img->pixels = tmp;
                memcpy(img->pixels + img->pixel_len,
                       chunk_data, chunk_len);
                img->pixel_len += chunk_len;
            }
        }
        break;
    case CHUNK_IEND:
        /* Mark end of stream */
        break;
    default:
        /* Ancillary chunk — ignored */
        break;
    }

    /*
     * Save the ctx pointer into ALL pending callback slots that don't
     * yet have a context assigned.  This models the pattern where a
     * cleanup callback captures a pointer to the "current" chunk ctx.
     */
    for (int i = 0; i < img->cb_count; i++) {
        if (img->cb_ctx[i] == NULL)
            img->cb_ctx[i] = ctx;   /* store raw ptr */
    }

    /*
     * FREE the chunk context — but img->cb_ctx[] still holds the ptr.
     * This is the UAF setup: the pointer is now dangling.
     */
    free(ctx->data);
    free(ctx);   /* <<< chunk_ctx_t freed here */
                 /* img->cb_ctx[i] is now a DANGLING POINTER */

    *consumed = 8 + chunk_len + 4;
    return 0;
}

/* ------------------------------------------------------------------ */
/* png_load — top-level entry                                           */
/* ------------------------------------------------------------------ */
int png_load(png_image_t *img, const uint8_t *data, size_t len)
{
    if (!img || !data) return -1;

    if (!png_check_signature(data, len)) {
        snprintf(img->error, sizeof(img->error), "Bad PNG signature");
        return -1;
    }

    size_t offset = PNG_SIG_LEN;
    while (offset < len) {
        size_t consumed = 0;
        int ret = png_process_chunk(img, data + offset,
                                    len - offset, &consumed);
        if (ret != 0) break;
        if (consumed == 0) break;
        offset += consumed;
    }
    return 0;
}
