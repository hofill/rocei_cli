#include "apdu.h"
#include "card.h"
#include <string.h>
#include <stdio.h>

static const uint8_t KNOWN_ATR[]    = ROCEI_ATR;
static const uint8_t AID_BASE[]     = ROCEI_AID_BASE;
static const uint8_t AID_PKI[]      = ROCEI_AID_PKI;

int rocei_atr_matches(const uint8_t *atr, size_t len) {
    if (len == ROCEI_ATR_LEN && memcmp(atr, KNOWN_ATR, len) == 0)
        return 1;
    fprintf(stderr, "Warning: unknown ATR, proceeding anyway\n");
    return 1;
}

/* Send a SELECT by AID command; ignore response body */
static int select_aid_raw(rocei_card_t *card, const uint8_t *aid, size_t aid_len) {
    uint8_t cmd[5 + 16];
    cmd[0] = 0x00; cmd[1] = 0xA4; cmd[2] = 0x04; cmd[3] = 0x04;
    cmd[4] = (uint8_t)aid_len;
    memcpy(cmd + 5, aid, aid_len);
    uint8_t resp[256];
    size_t resp_len = sizeof(resp);
    return rocei_transmit(card, cmd, 5 + aid_len, resp, &resp_len);
}

int rocei_select_aid(rocei_card_t *card) {
    /* IAS ECC requires selecting the root AID first, then the applet */
    int rc = select_aid_raw(card, AID_BASE, sizeof(AID_BASE));
    if (rc != ROCEI_OK) return rc;
    return select_aid_raw(card, AID_PKI, sizeof(AID_PKI));
}

int rocei_read_ef(rocei_card_t *card, uint16_t ef_id,
                  uint8_t *buf, size_t *len) {
    /* SELECT EF by short file ID */
    uint8_t sel[] = {
        0x00, 0xA4, 0x02, 0x04,
        0x02,
        (uint8_t)(ef_id >> 8), (uint8_t)(ef_id & 0xFF)
    };
    uint8_t resp[258];
    size_t resp_len = sizeof(resp);
    int rc = rocei_transmit(card, sel, sizeof(sel), resp, &resp_len);
    if (rc != ROCEI_OK) return rc;

    /* Chunked READ BINARY — 224 bytes per chunk (safe for T1) */
    size_t offset = 0;
    const size_t CHUNK = 224;
    while (1) {
        if (offset >= *len) return ROCEI_ERR_NOMEM;
        uint8_t read_cmd[] = {
            0x00, 0xB0,
            (uint8_t)(offset >> 8), (uint8_t)(offset & 0xFF),
            (uint8_t)(CHUNK > (*len - offset) ? (*len - offset) : CHUNK)
        };
        resp_len = sizeof(resp);
        rc = rocei_transmit(card, read_cmd, sizeof(read_cmd), resp, &resp_len);

        uint8_t sw1 = resp_len >= 2 ? resp[resp_len - 2] : 0;
        uint8_t sw2 = resp_len >= 2 ? resp[resp_len - 1] : 0;
        size_t data_len = resp_len >= 2 ? resp_len - 2 : 0;

        if (data_len > 0)
            memcpy(buf + offset, resp, data_len);
        offset += data_len;

        /* 6282 = end of file reached (partial read is still valid) */
        if (sw1 == 0x62 && sw2 == 0x82) break;
        if (rc != ROCEI_OK) break;
        if (data_len < CHUNK) break;    /* short read = done */
    }
    *len = offset;
    return ROCEI_OK;
}

int rocei_verify_pin(rocei_card_t *card, uint8_t pin_ref, const char *pin) {
    size_t pin_len = strlen(pin);
    if (pin_len > 12) {
        fprintf(stderr, "PIN too long\n");
        return ROCEI_ERR_AUTH;
    }
    /* 12-byte block: PIN bytes followed by 0xFF padding */
    uint8_t block[ROCEI_PIN_BLOCK];
    memset(block, 0xFF, sizeof(block));
    memcpy(block, pin, pin_len);

    uint8_t apdu[5 + ROCEI_PIN_BLOCK] = {
        0x00, 0x20, 0x00, pin_ref, ROCEI_PIN_BLOCK
    };
    memcpy(apdu + 5, block, ROCEI_PIN_BLOCK);

    uint8_t resp[4];
    size_t resp_len = sizeof(resp);
    int rc = rocei_transmit(card, apdu, sizeof(apdu), resp, &resp_len);
    memset(block, 0, sizeof(block));
    return rc;
}

/* ---------------------------------------------------------------- DATA applet */

static const uint8_t AID_DATA[] = ROCEI_AID_DATA;

int rocei_select_data_aid(rocei_card_t *card) {
    int rc = select_aid_raw(card, AID_BASE, sizeof(AID_BASE));
    if (rc != ROCEI_OK) return rc;
    return select_aid_raw(card, AID_DATA, sizeof(AID_DATA));
}

int rocei_read_dg(rocei_card_t *card, uint16_t dg_id, uint8_t *buf, size_t *len) {
    /* SELECT EF by file ID (P2=0x04 = return FCP) */
    uint8_t sel[] = {
        0x00, 0xA4, 0x02, 0x04,
        0x02,
        (uint8_t)(dg_id >> 8), (uint8_t)(dg_id & 0xFF)
    };
    uint8_t resp[258];
    size_t resp_len = sizeof(resp);
    int rc = rocei_transmit(card, sel, sizeof(sel), resp, &resp_len);
    if (rc != ROCEI_OK) return rc;

    /* Handle 61xx (GET RESPONSE) */
    if (resp_len >= 2 && resp[resp_len - 2] == 0x61) {
        uint8_t gr[] = {0x00, 0xC0, 0x00, 0x00, resp[resp_len - 1]};
        resp_len = sizeof(resp);
        rocei_transmit(card, gr, sizeof(gr), resp, &resp_len);
    }

    return rocei_read_ef(card, dg_id, buf, len);
}

int rocei_mse_set_sign(rocei_card_t *card) {
    /* MSE:SET for Internal Authenticate:
     * CLA=00 INS=22 P1=41 P2=A4 Lc=06 body=[80 01 04 84 01 8E]
     *   80 01 04  = algorithm reference (raw ECDSA, tag 0x80)
     *   84 01 8E  = key reference (tag 0x84, key_ref=0x8E) */
    uint8_t apdu[] = {
        0x00, 0x22, 0x41, 0xA4,
        0x06,
        0x80, 0x01, ROCEI_MSE_ALG,
        0x84, 0x01, ROCEI_KEY_REF
    };
    uint8_t resp[4];
    size_t resp_len = sizeof(resp);
    return rocei_transmit(card, apdu, sizeof(apdu), resp, &resp_len);
}

int rocei_sign(rocei_card_t *card, const uint8_t *hash, size_t hash_len,
               uint8_t *sig, size_t *sig_len) {
    /* Internal Authenticate: CLA=00 INS=88 P1=00 P2=00 Lc=<len> <hash> Le=00 */
    if (hash_len > 64) return ROCEI_ERR_APDU;
    uint8_t apdu[5 + 64 + 1];
    apdu[0] = 0x00; apdu[1] = 0x88; apdu[2] = 0x00; apdu[3] = 0x00;
    apdu[4] = (uint8_t)hash_len;
    memcpy(apdu + 5, hash, hash_len);
    apdu[5 + hash_len] = 0x00; /* Le */
    return rocei_transmit(card, apdu, 6 + hash_len, sig, sig_len);
}
