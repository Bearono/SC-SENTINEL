/*
 * adpcm_decoder.c — MS-ADPCM block decoder with OOB vulnerability
 *
 * Vulnerability: CWE-125 Out-of-Bounds Read  +  CWE-122 Heap OOB Write
 * Inspired by:   CVE-2021-3246 (libsndfile msadpcm_decode_block)
 *                CVE-2018-13139 (libsndfile psf_memset stack OOB)
 * Location:      adpcm_decode_block()  [line ~180]
 *
 * Root cause (two sub-bugs):
 *
 *  Sub-bug 1 — OOB Write (CVE-2021-3246 style):
 *    pcm_out is allocated for fmt.samples_per_block * channels samples.
 *    The decode loop drives its iteration count from the actual encoded
 *    nibbles in the block, not from samples_per_block.  A block that
 *    contains more nibble pairs than samples_per_block causes the output
 *    write index to exceed pcm_cap → heap-buffer-overflow (WRITE).
 *
 *  Sub-bug 2 — OOB Read:
 *    When block_len < expected (block_align), the nibble reader
 *    `in_pos++` advances past the end of the block array, reading
 *    uninitialized / out-of-bounds heap bytes as audio data.
 *    (Also: the block header reads 7 bytes per channel without checking
 *    block_len first → OOB read on tiny input.)
 */

#include "adpcm_decoder.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Standard MS-ADPCM coefficient table */
static const adpcm_coef_t std_coef[ADPCM_NUM_COEF] = {
    { 256,    0 },
    { 512, -256 },
    {   0,    0 },
    { 192,   64 },
    { 240,    0 },
    { 460, -208 },
    { 392, -232 },
};

/* Adaptation table */
static const int16_t adapt_table[16] = {
    230, 230, 230, 230, 307, 409, 512, 614,
    768, 614, 512, 409, 307, 230, 230, 230
};

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */
uint32_t wav_read_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

uint16_t wav_read_u16le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

int adpcm_clamp16(int v)
{
    if (v >  32767) return  32767;
    if (v < -32768) return -32768;
    return v;
}

/* ------------------------------------------------------------------ */
/* adpcm_ctx_new / free                                                 */
/* ------------------------------------------------------------------ */
adpcm_ctx_t *adpcm_ctx_new(void)
{
    return (adpcm_ctx_t *)calloc(1, sizeof(adpcm_ctx_t));
}

void adpcm_ctx_free(adpcm_ctx_t *ctx)
{
    if (!ctx) return;
    free(ctx->data);
    free(ctx->pcm_out);
    free(ctx);
}

/* ------------------------------------------------------------------ */
/* adpcm_parse_wav                                                      */
/* ------------------------------------------------------------------ */
int adpcm_parse_wav(adpcm_ctx_t *ctx,
                    const uint8_t *data, size_t len)
{
    if (!ctx || !data || len < 12) return -1;

    uint32_t riff_id   = wav_read_u32le(data + 0);
    uint32_t wave_id   = wav_read_u32le(data + 8);
    if (riff_id != RIFF_ID || wave_id != WAVE_ID) {
        snprintf(ctx->error, sizeof(ctx->error), "Not a RIFF/WAVE file");
        return -1;
    }

    size_t pos = 12;
    while (pos + 8 <= len) {
        uint32_t chunk_id  = wav_read_u32le(data + pos);
        uint32_t chunk_len = wav_read_u32le(data + pos + 4);
        pos += 8;

        if (pos + chunk_len > len) break;

        if (chunk_id == FMT_ID) {
            if (chunk_len < 18) { pos += chunk_len; continue; }
            wav_fmt_t *f = &ctx->fmt;
            f->format_tag      = wav_read_u16le(data + pos + 0);
            f->channels        = wav_read_u16le(data + pos + 2);
            f->sample_rate     = wav_read_u32le(data + pos + 4);
            f->byte_rate       = wav_read_u32le(data + pos + 8);
            f->block_align     = wav_read_u16le(data + pos + 12);
            f->bits_per_sample = wav_read_u16le(data + pos + 14);
            f->extra_size      = wav_read_u16le(data + pos + 16);
            if (chunk_len >= 20) {
                /* samples_per_block — ATTACKER CONTROLLED, not validated */
                f->samples_per_block = wav_read_u16le(data + pos + 18);
            }
            if (chunk_len >= 22) {
                f->num_coef = wav_read_u16le(data + pos + 20);
                if (f->num_coef > ADPCM_NUM_COEF)
                    f->num_coef = ADPCM_NUM_COEF;
                for (uint16_t i = 0; i < f->num_coef && pos + 22 + i*4 + 4 <= pos + chunk_len; i++) {
                    f->coef[i].coef1 = (int16_t)wav_read_u16le(data + pos + 22 + i*4);
                    f->coef[i].coef2 = (int16_t)wav_read_u16le(data + pos + 22 + i*4 + 2);
                }
            } else {
                /* Use standard table */
                memcpy(f->coef, std_coef, sizeof(std_coef));
                f->num_coef = ADPCM_NUM_COEF;
            }
            ctx->fmt_seen = 1;

        } else if (chunk_id == DATA_ID) {
            ctx->data = (uint8_t *)malloc(chunk_len + 1);
            if (!ctx->data) return -1;
            memcpy(ctx->data, data + pos, chunk_len);
            ctx->data_len = chunk_len;
        }

        pos += chunk_len + (chunk_len & 1);  /* word-align */
    }

    if (!ctx->fmt_seen) {
        snprintf(ctx->error, sizeof(ctx->error), "No fmt chunk");
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* VULNERABLE: adpcm_decode_block                                       */
/*                                                                     */
/* Bug 1 (OOB Write): output buffer allocated for samples_per_block   */
/*   samples, but decode loop may produce more samples than that.      */
/*                                                                     */
/* Bug 2 (OOB Read): block header read does not check block_len;      */
/*   nibble reader advances in_pos past end of block.                  */
/* ------------------------------------------------------------------ */
int adpcm_decode_block(adpcm_ctx_t *ctx,
                       const uint8_t *block, size_t block_len)
{
    if (!ctx || !block) return -1;

    int      channels         = ctx->fmt.channels ? ctx->fmt.channels : 1;
    uint16_t samples_per_blk  = ctx->fmt.samples_per_block;

    if (samples_per_blk == 0) samples_per_blk = 500;   /* fallback */

    /*
     * OUTPUT BUFFER: allocated exactly for samples_per_blk * channels.
     * BUG: if the encoded block contains more nibbles, out_idx will
     *      exceed this allocation → heap buffer overflow (OOB write).
     */
    size_t out_cap = (size_t)samples_per_blk * (size_t)channels;
    int16_t *out   = (int16_t *)realloc(ctx->pcm_out,
                                         (ctx->pcm_len + out_cap) * sizeof(int16_t));
    if (!out) return -1;
    ctx->pcm_out = out;
    ctx->pcm_cap = ctx->pcm_len + out_cap;

    adpcm_channel_t ch[2] = {0};
    size_t in_pos = 0;

    /* ---- Read per-channel block header (7 bytes each) ---- */
    for (int c = 0; c < channels; c++) {
        /*
         * OOB READ: no check that in_pos + 7 <= block_len.
         * A truncated block causes reads past the end.
         */
        ch[c].coef_idx = block[in_pos];          /* BUG: unchecked */
        in_pos++;
        ch[c].delta    = (int16_t)wav_read_u16le(block + in_pos);
        in_pos += 2;
        ch[c].prev[0]  = (int16_t)wav_read_u16le(block + in_pos);
        in_pos += 2;
        ch[c].prev[1]  = (int16_t)wav_read_u16le(block + in_pos);
        in_pos += 2;
    }

    /* Emit the two predictor samples from each channel header */
    size_t out_idx = ctx->pcm_len;
    for (int c = 0; c < channels; c++) {
        if (out_idx < ctx->pcm_cap)
            ctx->pcm_out[out_idx++] = ch[c].prev[1];
    }
    for (int c = 0; c < channels; c++) {
        if (out_idx < ctx->pcm_cap)
            ctx->pcm_out[out_idx++] = ch[c].prev[0];
    }

    /* ---- Decode nibble stream ---- */
    int chan = 0;
    while (in_pos < block_len) {
        uint8_t byte = block[in_pos++];   /* OOB READ if in_pos >= block_len */

        for (int nibble_idx = 1; nibble_idx >= 0; nibble_idx--) {
            int8_t nibble = (int8_t)((byte >> (nibble_idx * 4)) & 0x0F);
            if (nibble >= 8) nibble -= 16;   /* sign-extend 4-bit */

            adpcm_channel_t *c = &ch[chan % channels];
            uint8_t ci = c->coef_idx < ADPCM_NUM_COEF
                         ? c->coef_idx : 0;

            int predictor = ((int)c->prev[0] * std_coef[ci].coef1 +
                             (int)c->prev[1] * std_coef[ci].coef2) / 256
                            + (int)nibble * (int)c->delta;

            int16_t sample = (int16_t)adpcm_clamp16(predictor);

            /*
             * OOB WRITE: out_idx may exceed ctx->pcm_cap when
             * block_len encodes more samples than samples_per_block.
             * No bounds check here.
             */
            ctx->pcm_out[out_idx++] = sample;   /* BUG: unchecked */

            c->prev[1] = c->prev[0];
            c->prev[0] = sample;

            int16_t new_delta = (int16_t)(
                ((int)c->delta * adapt_table[nibble & 0xF]) / 256);
            if (new_delta < 16) new_delta = 16;
            c->delta = new_delta;
            chan++;
        }
    }

    ctx->pcm_len = out_idx;
    return (int)(out_idx - ctx->pcm_len + (out_idx > ctx->pcm_len
                 ? out_idx - ctx->pcm_len : 0));
}

/* ------------------------------------------------------------------ */
/* adpcm_decode_all                                                     */
/* ------------------------------------------------------------------ */
int adpcm_decode_all(adpcm_ctx_t *ctx)
{
    if (!ctx || !ctx->data || !ctx->fmt_seen) return -1;

    uint16_t block_align = ctx->fmt.block_align;
    if (block_align == 0) block_align = 256;

    size_t offset = 0;
    while (offset + block_align <= ctx->data_len) {
        int r = adpcm_decode_block(ctx,
                                   ctx->data + offset,
                                   block_align);
        if (r < 0) return -1;
        offset += block_align;
    }

    /* Decode partial trailing block (if any) */
    if (offset < ctx->data_len) {
        adpcm_decode_block(ctx,
                           ctx->data + offset,
                           ctx->data_len - offset);
    }
    return (int)ctx->pcm_len;
}
