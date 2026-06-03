/*
 * modbus_proto.c — Modbus TCP parser with stack buffer overflow
 *
 * Vulnerability: CWE-121 Stack-based Buffer Overflow
 * Inspired by:   CVE-2022-0367 (libmodbus modbus_reply heap OOB write)
 *                CVE-2024-10918 (libmodbus v3.1.10 stack overflow)
 * Location:      modbus_handle_fc17()  [line ~160]
 *
 * Root cause:
 *   Function code 0x17 (Read/Write Multiple Registers) requires the
 *   server to echo back nb_read register values.  modbus_handle_fc17()
 *   assembles the response into a stack-local array declared as
 *   RESP_BUF_SIZE (128) bytes, but nb_read can be up to 125 (registers)
 *   × 2 bytes = 250 bytes of data plus the 9-byte MBAP+PDU header =
 *   259 bytes total — overflowing the 128-byte stack buffer by 131 bytes.
 */

#include "modbus_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */
static uint16_t read_u16be(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void write_u16be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

/* ------------------------------------------------------------------ */
/* Mapping allocation                                                   */
/* ------------------------------------------------------------------ */
modbus_mapping_t *modbus_mapping_new(void)
{
    return (modbus_mapping_t *)calloc(1, sizeof(modbus_mapping_t));
}

void modbus_mapping_free(modbus_mapping_t *map)
{
    free(map);
}

/* ------------------------------------------------------------------ */
/* modbus_parse_request                                                 */
/* ------------------------------------------------------------------ */
int modbus_parse_request(const uint8_t *buf, size_t len,
                         modbus_request_t *req)
{
    if (!buf || !req || len < (size_t)(MBAP_LEN + 2)) return -1;

    memset(req, 0, sizeof(*req));

    req->transaction_id = read_u16be(buf + 0);
    req->protocol_id    = read_u16be(buf + 2);
    req->pdu_length     = read_u16be(buf + 4);
    req->unit_id        = buf[6];
    req->function_code  = buf[7];

    const uint8_t *pdu  = buf + MBAP_LEN + 1; /* skip unit_id */
    size_t         plen = len - MBAP_LEN - 1;

    switch (req->function_code) {

    case FC_READ_COILS:
    case FC_READ_HOLDING_REGS:
        if (plen < 5) return -1;
        req->read_addr = read_u16be(pdu + 1);
        req->nb_read   = read_u16be(pdu + 3);
        break;

    case FC_WRITE_SINGLE_REG:
        if (plen < 5) return -1;
        req->write_addr = read_u16be(pdu + 1);
        req->write_data[0] = pdu[3];
        req->write_data[1] = pdu[4];
        req->nb_write = 1;
        break;

    case FC_WRITE_MULTIPLE_REGS:
        if (plen < 6) return -1;
        req->write_addr  = read_u16be(pdu + 1);
        req->nb_write    = read_u16be(pdu + 3);
        req->write_count = pdu[5];
        if (plen < (size_t)(6 + req->write_count)) return -1;
        memcpy(req->write_data, pdu + 6,
               req->write_count < MODBUS_MAX_PDU
               ? req->write_count : MODBUS_MAX_PDU);
        break;

    case FC_READ_WRITE_REGS:
        if (plen < 10) return -1;
        req->read_addr   = read_u16be(pdu + 1);
        req->nb_read     = read_u16be(pdu + 3);  /* attacker-controlled */
        req->write_addr  = read_u16be(pdu + 5);
        req->nb_write    = read_u16be(pdu + 7);  /* attacker-controlled */
        req->write_count = pdu[9];
        if (plen < (size_t)(10 + req->write_count)) return -1;
        memcpy(req->write_data, pdu + 10,
               req->write_count < MODBUS_MAX_PDU
               ? req->write_count : MODBUS_MAX_PDU);
        break;

    default:
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* VULNERABLE FUNCTION: modbus_handle_fc17                             */
/*                                                                     */
/* Assembles a FC 0x17 response into a STACK-LOCAL buffer.             */
/* nb_read is not clamped → response body can be up to 250 bytes,     */
/* plus 9-byte header = 259 bytes → overflows RESP_BUF_SIZE (128).    */
/* ------------------------------------------------------------------ */
int modbus_handle_fc17(const modbus_request_t *req,
                       modbus_mapping_t *map)
{
    /*
     * VULNERABILITY: stack buffer sized RESP_BUF_SIZE = 128 bytes.
     * Legitimate maximum response = MBAP(6) + unit(1) + FC(1) +
     *   byte_count(1) + nb_read*2 bytes.
     * With nb_read = 125: 9 + 250 = 259 bytes → STACK OVERFLOW.
     */
    uint8_t  response[RESP_BUF_SIZE];   /* BUG: too small */
    uint16_t nb_read = req->nb_read;

    /* Build MBAP */
    write_u16be(response + 0, req->transaction_id);
    write_u16be(response + 2, 0x0000);          /* protocol */
    /* pdu_length filled in later */
    response[6] = req->unit_id;
    response[7] = FC_READ_WRITE_REGS;
    response[8] = (uint8_t)(nb_read * 2);       /* byte count */

    /* Copy register values — OVERFLOWS stack buffer when nb_read > ~59 */
    for (uint16_t i = 0; i < nb_read; i++) {
        uint16_t addr = req->read_addr + i;
        uint16_t val  = (addr < MODBUS_MAX_REGS) ? map->regs[addr] : 0;
        /*
         * STACK OVERFLOW HERE: when i * 2 + 9 >= RESP_BUF_SIZE (128),
         * i.e. i >= 59, writes past end of stack frame.
         */
        write_u16be(response + 9 + i * 2, val);
    }

    uint16_t pdu_len = (uint16_t)(2 + 1 + nb_read * 2);
    write_u16be(response + 4, pdu_len);

    /* Process write portion (side-effect on mapping) */
    for (uint16_t i = 0; i < req->nb_write && i < MODBUS_MAX_REGS; i++) {
        uint16_t addr = req->write_addr + i;
        if (addr < MODBUS_MAX_REGS && i * 2 + 1 < req->write_count) {
            map->regs[addr] = read_u16be(req->write_data + i * 2);
        }
    }

    return (int)(MBAP_LEN + 1 + 1 + 1 + nb_read * 2);
}

/* ------------------------------------------------------------------ */
/* modbus_build_response — safe wrapper (correct bounds)               */
/* ------------------------------------------------------------------ */
int modbus_build_response(const modbus_request_t *req,
                          const modbus_mapping_t *map,
                          uint8_t *out, size_t out_max)
{
    if (!req || !map || !out) return -1;
    size_t needed = MBAP_LEN + 1 + 1 + 1 + req->nb_read * 2;
    if (needed > out_max) return -1;

    write_u16be(out + 0, req->transaction_id);
    write_u16be(out + 2, 0x0000);
    out[6] = req->unit_id;
    out[7] = req->function_code;
    out[8] = (uint8_t)(req->nb_read * 2);

    for (uint16_t i = 0; i < req->nb_read; i++) {
        uint16_t addr = req->read_addr + i;
        uint16_t val  = (addr < MODBUS_MAX_REGS) ? map->regs[addr] : 0;
        write_u16be(out + 9 + i * 2, val);
    }
    uint16_t pdu_len = (uint16_t)(2 + 1 + req->nb_read * 2);
    write_u16be(out + 4, pdu_len);
    return (int)needed;
}

/* ------------------------------------------------------------------ */
/* modbus_reply — top-level entry                                       */
/* ------------------------------------------------------------------ */
int modbus_reply(modbus_mapping_t *map,
                 const uint8_t *req_buf, size_t req_len,
                 uint8_t *resp_buf, size_t resp_max)
{
    modbus_request_t req;
    if (modbus_parse_request(req_buf, req_len, &req) != 0) return -1;

    if (req.function_code == FC_READ_WRITE_REGS) {
        /* Route through vulnerable handler */
        return modbus_handle_fc17(&req, map);
    }
    return modbus_build_response(&req, map, resp_buf, resp_max);
}
