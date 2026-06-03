#ifndef MODBUS_PROTO_H
#define MODBUS_PROTO_H

/*
 * Modbus TCP protocol parser — minimal implementation
 * CWE-121: Stack-based Buffer Overflow
 * Inspired by: CVE-2022-0367 (libmodbus heap overflow in modbus_reply)
 *              CVE-2024-10918 (libmodbus stack overflow v3.1.10)
 *
 * Root cause (this implementation):
 *   modbus_build_response() uses a fixed-size stack buffer to assemble
 *   the response PDU.  The 'nb_write' field from the request is not
 *   validated before computing the response body size, allowing a
 *   crafted request to produce a response that overflows the stack buffer.
 */

#include <stdint.h>
#include <stddef.h>

/* Modbus TCP MBAP header: 6 bytes */
#define MBAP_LEN            6
/* Maximum legitimate PDU payload */
#define MODBUS_MAX_PDU      253
/* STACK BUFFER SIZE — intentionally smaller than max possible response */
#define RESP_BUF_SIZE       128   /* BUG: should be MODBUS_MAX_PDU+MBAP_LEN */

/* Function codes */
#define FC_READ_COILS           0x01
#define FC_READ_HOLDING_REGS    0x03
#define FC_WRITE_SINGLE_REG     0x06
#define FC_WRITE_MULTIPLE_REGS  0x10
#define FC_READ_WRITE_REGS      0x17   /* CVE-2022-0367 path */

/* Simulated register map */
#define MODBUS_MAX_REGS     512

typedef struct {
    uint16_t regs[MODBUS_MAX_REGS];
    uint8_t  coils[MODBUS_MAX_REGS];
} modbus_mapping_t;

/* Parsed Modbus TCP request */
typedef struct {
    uint16_t transaction_id;
    uint16_t protocol_id;
    uint16_t pdu_length;
    uint8_t  unit_id;
    uint8_t  function_code;
    /* FC-specific fields */
    uint16_t read_addr;
    uint16_t nb_read;
    uint16_t write_addr;
    uint16_t nb_write;      /* DANGEROUS: drives response buffer size */
    uint8_t  write_count;   /* byte count for write data */
    uint8_t  write_data[MODBUS_MAX_PDU];
} modbus_request_t;

/* Public API */
modbus_mapping_t *modbus_mapping_new(void);
void              modbus_mapping_free(modbus_mapping_t *map);

int  modbus_parse_request(const uint8_t *buf, size_t len,
                          modbus_request_t *req);
int  modbus_build_response(const modbus_request_t *req,
                           const modbus_mapping_t *map,
                           uint8_t *out, size_t out_max);    /* safe wrapper */
int  modbus_reply(modbus_mapping_t *map,
                  const uint8_t *req_buf, size_t req_len,
                  uint8_t *resp_buf, size_t resp_max);

/* Internal — exposed for Agent C */
int  modbus_handle_fc17(const modbus_request_t *req,        /* VULNERABLE */
                        modbus_mapping_t *map);

#endif /* MODBUS_PROTO_H */
