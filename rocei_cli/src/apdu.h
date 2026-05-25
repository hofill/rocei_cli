#pragma once
#include <stdint.h>
#include <stddef.h>
#include "card.h"

/* ATR of the Romanian eID */
#define ROCEI_ATR     { \
    0x3B,0xDF,0x96,0x00,0x81,0x31,0xFE,0x45, \
    0x80,0x73,0x84,0x21,0xE0,0x55,0x69,0x78, \
    0x00,0x00,0x80,0x83,0x07,0x90,0x00,0x24  \
}
#define ROCEI_ATR_LEN 24

/* Application Identifiers */
#define ROCEI_AID_BASE      { 0xA0,0x00,0x00,0x00,0x77 }
#define ROCEI_AID_BASE_LEN  5
#define ROCEI_AID_PKI       { 0xE8,0x28,0xBD,0x08,0x0F,0xD2,0x50,0x47,0x65,0x6E,0x65,0x72,0x69,0x63 }
#define ROCEI_AID_PKI_LEN   14
#define ROCEI_AID_DATA      { 0xE8,0x28,0xBD,0x08,0x0F,0xA0,0x00,0x00,0x01,0x67,0x45,0x44,0x41,0x54,0x41 }
#define ROCEI_AID_DATA_LEN  15

/* Elementary File IDs */
#define ROCEI_EF_SIGN_CERT  0xCE8E   /* signing certificate (DER, ~996 bytes) in PKI applet */
#define ROCEI_DG_FIRST      0x0101   /* first personal data group in DATA applet */
#define ROCEI_DG_LAST       0x0110   /* last DG to probe */

/* PIN references and block format */
#define ROCEI_PIN_REF_SIGN  0x05     /* Advanced Signature PIN (6-digit) */
#define ROCEI_PIN_REF_DATA  0x03     /* Data access PIN (4-digit) */
#define ROCEI_PIN_REF       ROCEI_PIN_REF_SIGN
#define ROCEI_PIN_BLOCK     12       /* padded block length (unused bytes = 0xFF) */

/* MSE:SET / Internal Authenticate key reference */
#define ROCEI_KEY_REF   0x8E
#define ROCEI_MSE_ALG   0x04

/* APDU helpers — PKI applet */
int rocei_atr_matches(const uint8_t *atr, size_t len);
int rocei_select_aid(rocei_card_t *card);
int rocei_read_ef(rocei_card_t *card, uint16_t ef_id, uint8_t *buf, size_t *len);
int rocei_verify_pin(rocei_card_t *card, uint8_t pin_ref, const char *pin);
int rocei_mse_set_sign(rocei_card_t *card);
int rocei_sign(rocei_card_t *card, const uint8_t *hash, size_t hash_len,
               uint8_t *sig, size_t *sig_len);

/* APDU helpers — DATA applet */
int rocei_select_data_aid(rocei_card_t *card);
int rocei_read_dg(rocei_card_t *card, uint16_t dg_id, uint8_t *buf, size_t *len);
