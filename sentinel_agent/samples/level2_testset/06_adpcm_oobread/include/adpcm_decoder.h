#ifndef ADPCM_DECODER_H
#define ADPCM_DECODER_H

/*
 * MS-ADPCM audio block decoder
 * CWE-125: Out-of-Bounds Read (heap)
 * Inspired by: CVE-2021-3246 (libsndfile msadpcm_decode_block heap OOB write)
 *              CVE-2018-13139 (libsndfile stack OOB write in psf_memset)
 *
 * Root cause:
 *   adpcm_decode_block() derives the number of output samples from the
 *   WAV chunk header field 'samples_per_block'.  This value is taken
 *   directly from attacker-controlled input without validation.
 *
 *   The output buffer is sized according to the FORMAT chunk's declared
 *   samples_per_block, but the decode loop iterates over the actual DATA
 *   chunk bytes — which may encode more samples than declared.
 *
 *   Result: the write index 'out_idx' exceeds the allocated output buffer,
 *   producing a heap buffer overflow (OOB write) for CVE-2021-3246 style,
 *   or an OOB read of the input nibble stream when block_size is too small.
 */

#include <stddef.h>
#include <stdint.h>

/* WAV RIFF chunk IDs */
#define RIFF_ID  0x46464952U  /* "RIFF" */
#define WAVE_ID  0x45564157U  /* "WAVE" */
#define FMT_ID   0x20746D66U  /* "fmt " */
#define DATA_ID  0x61746164U  /* "data" */

/* MS-ADPCM format tag */
#define WAVE_FORMAT_MS_ADPCM   0x0002

/* ADPCM coefficient pairs (7 standard sets) */
#define ADPCM_NUM_COEF  7

typedef struct {
    int16_t coef1;
    int16_t coef2;
} adpcm_coef_t;

/* WAV format descriptor */
typedef struct {
    uint16_t format_tag;
    uint16_t channels;
    uint32_t sample_rate;
    uint32_t byte_rate;
    uint16_t block_align;        /* bytes per encoded block */
    uint16_t bits_per_sample;
    uint16_t extra_size;
    uint16_t samples_per_block;  /* DANGEROUS: from file, not validated */
    uint16_t num_coef;
    adpcm_coef_t coef[ADPCM_NUM_COEF];
} wav_fmt_t;

/* Per-channel ADPCM decode state */
typedef struct {
    int16_t  prev[2];    /* two previous samples */
    int16_t  delta;
    uint8_t  coef_idx;
} adpcm_channel_t;

/* Top-level decoder context */
typedef struct {
    wav_fmt_t        fmt;
    int              fmt_seen;

    uint8_t         *data;       /* raw DATA chunk bytes */
    size_t           data_len;

    int16_t         *pcm_out;    /* decoded PCM (heap) */
    size_t           pcm_len;    /* samples written */
    size_t           pcm_cap;    /* allocated samples */

    char             error[128];
} adpcm_ctx_t;

/* Public API */
adpcm_ctx_t *adpcm_ctx_new(void);
void         adpcm_ctx_free(adpcm_ctx_t *ctx);

int  adpcm_parse_wav(adpcm_ctx_t *ctx,
                     const uint8_t *data, size_t len);
int  adpcm_decode_block(adpcm_ctx_t *ctx,
                        const uint8_t *block, size_t block_len); /* VULNERABLE */
int  adpcm_decode_all(adpcm_ctx_t *ctx);

/* Internal helpers */
uint32_t wav_read_u32le(const uint8_t *p);
uint16_t wav_read_u16le(const uint8_t *p);
int      adpcm_clamp16(int v);

#endif /* ADPCM_DECODER_H */
