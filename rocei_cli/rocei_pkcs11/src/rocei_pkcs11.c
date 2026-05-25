#include "pkcs11_platform.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#  include <strings.h>
#endif

#define ROCEI_MAX_SESSIONS 16
#define ROCEI_MAX_SEARCH_RESULTS 8
#define ROCEI_MAX_CERT_SIZE 16384
#define ROCEI_MAX_META_SIZE 1024
#define ROCEI_MAX_SIG_SIZE 132
#define ROCEI_SLOT_BASE 1

#define ROCEI_CERT_HANDLE       ((CK_OBJECT_HANDLE)0x80000030UL)
#define ROCEI_PRIVATE_KEY_HANDLE ((CK_OBJECT_HANDLE)0x80000020UL)
#define ROCEI_PUBLIC_KEY_HANDLE  ((CK_OBJECT_HANDLE)0x80000018UL)

#define ROCEI_APP_NONE 0
#define ROCEI_APP_PKI  1
#define ROCEI_APP_QSCD 2

static const uint8_t ROCEI_OLD_ATR[] = {
    0x3B,0xDF,0x96,0x00,0x81,0x31,0xFE,0x45,0x80,0x73,0x84,0x21,
    0xE0,0x55,0x69,0x78,0x00,0x00,0x80,0x83,0x07,0x90,0x00,0x24
};

static const uint8_t AID_BASE[] = {
    0xA0,0x00,0x00,0x00,0x77
};

static const uint8_t AID_PKI[] = {
    0xE8,0x28,0xBD,0x08,0x0F,0xD2,0x50,0x47,0x65,0x6E,0x65,0x72,0x69,0x63
};

static const uint8_t AID_QSCD[] = {
    0xE8,0x28,0xBD,0x08,0x0F,0xA0,0x00,0x00,0x01,0x67,0x45,0x53,0x49,0x47,0x4E
};

static const uint8_t ROCEI_OBJECT_ID[] = {
    0x52,0x4F,0x43,0x45,0x49,0x2D,0x53,0x49,0x47,0x4E
};

static const uint8_t EC_PARAMS_PRIME256V1[] = {
    0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07
};

static const char CERT_LABEL[] = "Certificate ECC Advanced Signature";
static const char PRIV_LABEL[] = "Private Key ECC Advanced Signature";
static const char PUB_LABEL[]  = "Public Key ECC Advanced Signature";

typedef struct {
    int in_use;
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slot_id;
    int rw;
    int logged_in;

    SCARDCONTEXT ctx;
    SCARDHANDLE card;
    DWORD protocol;
    int selected_app;
    int pin_cached;
    int pin_app;
    uint8_t pin_ref;
    uint8_t pin_padded[12];

    int cert_attempted;
    int cert_loaded;
    uint8_t cert[ROCEI_MAX_CERT_SIZE];
    size_t cert_len;
    uint8_t subject[ROCEI_MAX_META_SIZE];
    size_t subject_len;
    uint8_t issuer[ROCEI_MAX_META_SIZE];
    size_t issuer_len;
    uint8_t serial[ROCEI_MAX_META_SIZE];
    size_t serial_len;
    uint8_t ec_params[64];
    size_t ec_params_len;
    uint8_t ec_point[160];
    size_t ec_point_len;

    int sign_active;
    CK_MECHANISM_TYPE sign_mechanism;
    CK_OBJECT_HANDLE sign_key;
    uint8_t *sign_buf;
    size_t sign_len;
    size_t sign_cap;

    CK_OBJECT_HANDLE search_results[ROCEI_MAX_SEARCH_RESULTS];
    CK_ULONG search_count;
    CK_ULONG search_index;
    int search_active;
} rocei_session_t;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_initialized = 0;
static CK_SESSION_HANDLE g_next_session = 1;
static rocei_session_t g_sessions[ROCEI_MAX_SESSIONS];

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

static void copy_padded(uint8_t *dst, size_t dst_len, const char *src) {
    size_t len = strlen(src);
    if (len > dst_len) len = dst_len;
    memset(dst, ' ', dst_len);
    memcpy(dst, src, len);
}

static uint16_t read_env_u16(const char *name, uint16_t fallback) {
    const char *v = getenv(name);
    if (!v || !*v) return fallback;
    char *end = NULL;
    unsigned long parsed = strtoul(v, &end, 0);
    if (end == v || parsed > 0xFFFFUL) return fallback;
    return (uint16_t)parsed;
}

static uint32_t read_env_u32(const char *name, uint32_t fallback) {
    const char *v = getenv(name);
    if (!v || !*v) return fallback;
    char *end = NULL;
    unsigned long parsed = strtoul(v, &end, 0);
    if (end == v || parsed > 0xFFFFFFFFUL) return fallback;
    return (uint32_t)parsed;
}

static uint8_t read_env_u8(const char *name, uint8_t fallback) {
    return (uint8_t)read_env_u16(name, fallback);
}

static int response_ok(const uint8_t *resp, size_t len) {
    return len >= 2 && resp[len - 2] == 0x90 && resp[len - 1] == 0x00;
}

static uint16_t response_sw(const uint8_t *resp, size_t len) {
    if (len < 2) return 0;
    return (uint16_t)((resp[len - 2] << 8) | resp[len - 1]);
}

static void debug_sw(const char *op, const uint8_t *resp, size_t len) {
    if (!getenv("ROCEI_DEBUG")) return;
    fprintf(stderr, "rocei_pkcs11: %s SW=%04X len=%zu\n", op, response_sw(resp, len), len);
}

static void debug_hex(const char *op, const uint8_t *buf, size_t len) {
    if (!getenv("ROCEI_DEBUG")) return;
    fprintf(stderr, "rocei_pkcs11: %s", op);
    for (size_t i = 0; i < len; i++) fprintf(stderr, " %02X", buf[i]);
    fprintf(stderr, "\n");
}

static int atr_matches(const uint8_t *atr, size_t len) {
    if (len == sizeof(ROCEI_OLD_ATR) && memcmp(atr, ROCEI_OLD_ATR, len) == 0)
        return 1;
    return getenv("ROCEI_ACCEPT_UNKNOWN_ATR") != NULL;
}

static CK_RV establish_context(SCARDCONTEXT *ctx) {
    LONG rv = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, ctx);
    return rv == SCARD_S_SUCCESS ? CKR_OK : CKR_DEVICE_ERROR;
}

static CK_RV get_reader_name(CK_SLOT_ID slot_id, char *out, size_t out_len) {
    if (slot_id < ROCEI_SLOT_BASE) return CKR_SLOT_ID_INVALID;

    SCARDCONTEXT ctx;
    CK_RV ckr = establish_context(&ctx);
    if (ckr != CKR_OK) return ckr;

    char readers[4096];
    DWORD readers_len = sizeof(readers);
    LONG rv = SCardListReaders(ctx, NULL, readers, &readers_len);
    if (rv != SCARD_S_SUCCESS) {
        SCardReleaseContext(ctx);
        return CKR_TOKEN_NOT_PRESENT;
    }

    CK_SLOT_ID wanted = slot_id - ROCEI_SLOT_BASE;
    CK_SLOT_ID idx = 0;
    const char *p = readers;
    while (*p) {
        size_t len = strlen(p);
        if (idx == wanted) {
            if (len + 1 > out_len) {
                SCardReleaseContext(ctx);
                return CKR_GENERAL_ERROR;
            }
            memcpy(out, p, len + 1);
            SCardReleaseContext(ctx);
            return CKR_OK;
        }
        p += len + 1;
        idx++;
    }

    SCardReleaseContext(ctx);
    return CKR_SLOT_ID_INVALID;
}

static int reader_has_rocei_card(const char *reader) {
    SCARDCONTEXT ctx;
    if (establish_context(&ctx) != CKR_OK) return 0;

    SCARD_READERSTATE_A rs;
    memset(&rs, 0, sizeof(rs));
    rs.szReader = reader;
    rs.dwCurrentState = SCARD_STATE_UNAWARE;

    LONG rv = SCardGetStatusChange(ctx, 0, &rs, 1);
    SCardReleaseContext(ctx);
    if (rv != SCARD_S_SUCCESS) return 0;
    if (rs.dwEventState & (SCARD_STATE_EMPTY | SCARD_STATE_UNAVAILABLE)) return 0;
    if (!(rs.dwEventState & SCARD_STATE_PRESENT)) return 0;
    return atr_matches(rs.rgbAtr, (size_t)rs.cbAtr);
}

static CK_RV connect_session_card(rocei_session_t *s) {
    char reader[512];
    CK_RV ckr = get_reader_name(s->slot_id, reader, sizeof(reader));
    if (ckr != CKR_OK) return ckr;

    ckr = establish_context(&s->ctx);
    if (ckr != CKR_OK) return ckr;

    LONG rv = SCardConnect(s->ctx, reader, SCARD_SHARE_SHARED,
                           SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                           &s->card, &s->protocol);
    if (rv == (LONG)SCARD_E_SHARING_VIOLATION) {
        /* macOS CryptoTokenKit may hold the card; try exclusive briefly */
        rv = SCardConnect(s->ctx, reader, SCARD_SHARE_EXCLUSIVE,
                          SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                          &s->card, &s->protocol);
    }
    if (rv != SCARD_S_SUCCESS) {
        SCardReleaseContext(s->ctx);
        s->ctx = 0;
        return CKR_TOKEN_NOT_PRESENT;
    }

    uint8_t atr[64];
    DWORD atr_len = sizeof(atr);
    DWORD state;
    char rdr[256];
    DWORD rdr_len = sizeof(rdr);
    rv = SCardStatus(s->card, rdr, &rdr_len, &state, &s->protocol, atr, &atr_len);
    if (rv != SCARD_S_SUCCESS || !atr_matches(atr, atr_len)) {
        SCardDisconnect(s->card, SCARD_LEAVE_CARD);
        SCardReleaseContext(s->ctx);
        s->card = 0;
        s->ctx = 0;
        return CKR_TOKEN_NOT_RECOGNIZED;
    }

    return CKR_OK;
}

static const SCARD_IO_REQUEST *active_pci(const rocei_session_t *s) {
    return s->protocol == SCARD_PROTOCOL_T0 ? SCARD_PCI_T0 : SCARD_PCI_T1;
}

static CK_RV tx_raw(rocei_session_t *s, const uint8_t *cmd, size_t cmd_len,
                    uint8_t *resp, size_t *resp_len) {
    DWORD recv_len = (DWORD)*resp_len;
    LONG rv = SCardTransmit(s->card, active_pci(s), cmd, (DWORD)cmd_len,
                            NULL, resp, &recv_len);
    if (rv != SCARD_S_SUCCESS) return CKR_DEVICE_ERROR;
    *resp_len = recv_len;
    return CKR_OK;
}

static CK_RV tx(rocei_session_t *s, const uint8_t *cmd, size_t cmd_len,
                uint8_t *resp, size_t *resp_len) {
    size_t resp_cap = *resp_len;
    CK_RV ckr = tx_raw(s, cmd, cmd_len, resp, resp_len);
    if (ckr != CKR_OK || *resp_len < 2) return ckr == CKR_OK ? CKR_DEVICE_ERROR : ckr;

    if (resp[*resp_len - 2] == 0x6C && cmd_len >= 5) {
        uint8_t retry[512];
        if (cmd_len > sizeof(retry)) return CKR_ARGUMENTS_BAD;
        memcpy(retry, cmd, cmd_len);
        retry[cmd_len - 1] = resp[*resp_len - 1];
        *resp_len = resp_cap;
        ckr = tx_raw(s, retry, cmd_len, resp, resp_len);
        if (ckr != CKR_OK || *resp_len < 2) return ckr == CKR_OK ? CKR_DEVICE_ERROR : ckr;
    }

    if (resp[*resp_len - 2] == 0x61) {
        uint8_t combined[4096];
        size_t combined_len = *resp_len - 2;
        if (combined_len > sizeof(combined)) return CKR_DEVICE_ERROR;
        memcpy(combined, resp, combined_len);

        uint8_t le = resp[*resp_len - 1];
        for (int i = 0; i < 8; i++) {
            uint8_t get_response[5] = {0x00,0xC0,0x00,0x00,le};
            uint8_t chunk[4096];
            size_t chunk_len = sizeof(chunk);
            ckr = tx_raw(s, get_response, sizeof(get_response), chunk, &chunk_len);
            if (ckr != CKR_OK || chunk_len < 2) return ckr == CKR_OK ? CKR_DEVICE_ERROR : ckr;
            if (combined_len + chunk_len > sizeof(combined)) return CKR_DEVICE_ERROR;
            memcpy(combined + combined_len, chunk, chunk_len);
            combined_len += chunk_len;
            if (chunk[chunk_len - 2] != 0x61) break;
            combined_len -= 2;
            le = chunk[chunk_len - 1];
        }

        if (combined_len > resp_cap) return CKR_BUFFER_TOO_SMALL;
        memcpy(resp, combined, combined_len);
        *resp_len = combined_len;
    }

    return CKR_OK;
}

static CK_RV select_aid_direct(rocei_session_t *s, const uint8_t *aid, size_t aid_len) {
    uint8_t cmd[5 + 32];
    if (aid_len > 32) return CKR_ARGUMENTS_BAD;
    cmd[0] = 0x00;
    cmd[1] = 0xA4;
    cmd[2] = 0x04;
    cmd[3] = 0x04;
    cmd[4] = (uint8_t)aid_len;
    memcpy(cmd + 5, aid, aid_len);
    uint8_t resp[4096];
    size_t resp_len = sizeof(resp);
    CK_RV ckr = tx(s, cmd, 5 + aid_len, resp, &resp_len);
    if (ckr != CKR_OK) return ckr;
    debug_sw("SELECT AID", resp, resp_len);
    if (!response_ok(resp, resp_len)) return CKR_DEVICE_ERROR;
    if (aid_len == sizeof(AID_PKI) && memcmp(aid, AID_PKI, aid_len) == 0)
        s->selected_app = ROCEI_APP_PKI;
    else if (aid_len == sizeof(AID_QSCD) && memcmp(aid, AID_QSCD, aid_len) == 0)
        s->selected_app = ROCEI_APP_QSCD;
    else
        s->selected_app = ROCEI_APP_NONE;
    return CKR_OK;
}

static CK_RV select_aid(rocei_session_t *s, const uint8_t *aid, size_t aid_len) {
    if (!(aid_len == sizeof(AID_BASE) && memcmp(aid, AID_BASE, aid_len) == 0)) {
        CK_RV ckr = select_aid_direct(s, AID_BASE, sizeof(AID_BASE));
        if (ckr != CKR_OK) return ckr;
    }
    return select_aid_direct(s, aid, aid_len);
}

static CK_RV select_ef(rocei_session_t *s, uint16_t fid) {
    uint8_t cmd[7] = {0x00,0xA4,0x02,0x04,0x02,(uint8_t)(fid >> 8),(uint8_t)fid};
    uint8_t resp[4096];
    size_t resp_len = sizeof(resp);
    CK_RV ckr = tx(s, cmd, sizeof(cmd), resp, &resp_len);
    if (ckr != CKR_OK) return ckr;
    debug_sw("SELECT EF", resp, resp_len);
    return response_ok(resp, resp_len) ? CKR_OK : CKR_DEVICE_ERROR;
}

static int der_total_length(const uint8_t *buf, size_t len, size_t *total) {
    if (len < 2 || buf[0] != 0x30) return 0;
    if ((buf[1] & 0x80) == 0) {
        *total = 2 + buf[1];
        return 1;
    }
    size_t n = buf[1] & 0x7F;
    if (n == 0 || n > sizeof(size_t) || len < 2 + n) return 0;
    size_t v = 0;
    for (size_t i = 0; i < n; i++) v = (v << 8) | buf[2 + i];
    *total = 2 + n + v;
    return 1;
}

static CK_RV read_selected_ef(rocei_session_t *s, uint8_t *out, size_t out_max, size_t *out_len) {
    size_t off = 0;
    size_t expected = 0;
    *out_len = 0;

    while (off < out_max) {
        size_t want = out_max - off;
        if (want > 0xE0) want = 0xE0;
        uint8_t cmd[5] = {0x00,0xB0,(uint8_t)(off >> 8),(uint8_t)off,(uint8_t)want};
        uint8_t resp[4096];
        size_t resp_len = sizeof(resp);
        CK_RV ckr = tx(s, cmd, sizeof(cmd), resp, &resp_len);
        if (ckr != CKR_OK || resp_len < 2) return ckr == CKR_OK ? CKR_DEVICE_ERROR : ckr;
        debug_sw("READ BINARY", resp, resp_len);

        uint16_t sw = response_sw(resp, resp_len);
        size_t data_len = resp_len - 2;

        if (sw == 0x6282 && data_len > 0) {
            if (off + data_len > out_max) return CKR_BUFFER_TOO_SMALL;
            memcpy(out + off, resp, data_len);
            off += data_len;
            break;
        }
        if (sw != 0x9000) break;
        if (data_len == 0) break;
        if (off + data_len > out_max) return CKR_BUFFER_TOO_SMALL;
        memcpy(out + off, resp, data_len);
        off += data_len;

        if (expected == 0 && der_total_length(out, off, &expected) && expected <= off)
            break;
        if (expected != 0 && off >= expected)
            break;
        if (data_len < want)
            break;
    }

    *out_len = off;
    return off > 0 ? CKR_OK : CKR_DEVICE_ERROR;
}

typedef struct {
    uint8_t tag;
    size_t start;
    size_t header_len;
    size_t value;
    size_t len;
    size_t end;
} tlv_t;

static int parse_tlv(const uint8_t *buf, size_t buf_len, size_t pos, tlv_t *tlv) {
    if (pos + 2 > buf_len) return 0;
    size_t p = pos;
    tlv->tag = buf[p++];
    if ((buf[p] & 0x80) == 0) {
        tlv->len = buf[p++];
    } else {
        size_t n = buf[p++] & 0x7F;
        if (n == 0 || n > sizeof(size_t) || p + n > buf_len) return 0;
        size_t len = 0;
        for (size_t i = 0; i < n; i++) len = (len << 8) | buf[p++];
        tlv->len = len;
    }
    if (p + tlv->len > buf_len) return 0;
    tlv->start = pos;
    tlv->header_len = p - pos;
    tlv->value = p;
    tlv->end = p + tlv->len;
    return 1;
}

static void copy_tlv_field(uint8_t *dst, size_t *dst_len, const uint8_t *buf, const tlv_t *tlv) {
    size_t len = tlv->end - tlv->start;
    if (len > ROCEI_MAX_META_SIZE) len = ROCEI_MAX_META_SIZE;
    memcpy(dst, buf + tlv->start, len);
    *dst_len = len;
}

static int encode_octet_string(const uint8_t *point, size_t point_len, uint8_t *out, size_t *out_len) {
    if (point_len + 4 > *out_len) return 0;
    size_t p = 0;
    out[p++] = 0x04;
    if (point_len < 0x80) {
        out[p++] = (uint8_t)point_len;
    } else if (point_len <= 0xFF) {
        out[p++] = 0x81;
        out[p++] = (uint8_t)point_len;
    } else {
        return 0;
    }
    memcpy(out + p, point, point_len);
    p += point_len;
    *out_len = p;
    return 1;
}

static void parse_cert_metadata(rocei_session_t *s) {
    s->subject_len = s->issuer_len = s->serial_len = 0;
    memcpy(s->ec_params, EC_PARAMS_PRIME256V1, sizeof(EC_PARAMS_PRIME256V1));
    s->ec_params_len = sizeof(EC_PARAMS_PRIME256V1);
    s->ec_point_len = 0;

    tlv_t cert, tbs;
    if (!parse_tlv(s->cert, s->cert_len, 0, &cert) || cert.tag != 0x30) return;
    if (!parse_tlv(s->cert, s->cert_len, cert.value, &tbs) || tbs.tag != 0x30) return;

    size_t p = tbs.value;
    tlv_t cur;
    if (!parse_tlv(s->cert, s->cert_len, p, &cur)) return;
    if (cur.tag == 0xA0) p = cur.end;

    tlv_t serial;
    if (!parse_tlv(s->cert, s->cert_len, p, &serial) || serial.tag != 0x02) return;
    copy_tlv_field(s->serial, &s->serial_len, s->cert, &serial);
    p = serial.end;

    if (!parse_tlv(s->cert, s->cert_len, p, &cur)) return; /* signature */
    p = cur.end;

    tlv_t issuer;
    if (!parse_tlv(s->cert, s->cert_len, p, &issuer) || issuer.tag != 0x30) return;
    copy_tlv_field(s->issuer, &s->issuer_len, s->cert, &issuer);
    p = issuer.end;

    if (!parse_tlv(s->cert, s->cert_len, p, &cur)) return; /* validity */
    p = cur.end;

    tlv_t subject;
    if (!parse_tlv(s->cert, s->cert_len, p, &subject) || subject.tag != 0x30) return;
    copy_tlv_field(s->subject, &s->subject_len, s->cert, &subject);
    p = subject.end;

    tlv_t spki;
    if (!parse_tlv(s->cert, s->cert_len, p, &spki) || spki.tag != 0x30) return;
    size_t sp = spki.value;
    tlv_t alg, bitstr;
    if (!parse_tlv(s->cert, s->cert_len, sp, &alg) || alg.tag != 0x30) return;
    size_t ap = alg.value;
    tlv_t oid;
    if (!parse_tlv(s->cert, s->cert_len, ap, &oid)) return;
    ap = oid.end;
    tlv_t params;
    if (parse_tlv(s->cert, s->cert_len, ap, &params) && params.tag == 0x06) {
        size_t len = params.end - params.start;
        if (len <= sizeof(s->ec_params)) {
            memcpy(s->ec_params, s->cert + params.start, len);
            s->ec_params_len = len;
        }
    }
    sp = alg.end;
    if (!parse_tlv(s->cert, s->cert_len, sp, &bitstr) || bitstr.tag != 0x03) return;
    if (bitstr.len < 2 || s->cert[bitstr.value] != 0x00) return;
    size_t point_len = bitstr.len - 1;
    size_t out_len = sizeof(s->ec_point);
    if (encode_octet_string(s->cert + bitstr.value + 1, point_len, s->ec_point, &out_len))
        s->ec_point_len = out_len;
}

static CK_RV load_certificate(rocei_session_t *s) {
    if (s->cert_loaded) return CKR_OK;
    if (s->cert_attempted) return CKR_DEVICE_ERROR;
    s->cert_attempted = 1;

    const char *cert_app = getenv("ROCEI_CERT_APP");
    CK_RV ckr;
    if (cert_app && strcasecmp(cert_app, "qscd") == 0)
        ckr = select_aid(s, AID_QSCD, sizeof(AID_QSCD));
    else
        ckr = select_aid(s, AID_PKI, sizeof(AID_PKI));
    if (ckr != CKR_OK) return ckr;

    uint16_t cert_fid = read_env_u16("ROCEI_CERT_FID", 0xCE8E);
    ckr = select_ef(s, cert_fid);
    if (ckr != CKR_OK) return ckr;

    size_t len = 0;
    ckr = read_selected_ef(s, s->cert, sizeof(s->cert), &len);
    if (ckr != CKR_OK) return ckr;

    if (len > 0 && s->cert[0] != 0x30) {
        for (size_t i = 1; i < len && i < 32; i++) {
            if (s->cert[i] == 0x30) {
                memmove(s->cert, s->cert + i, len - i);
                len -= i;
                break;
            }
        }
    }

    size_t der_len = 0;
    if (der_total_length(s->cert, len, &der_len) && der_len <= len)
        len = der_len;

    if (len < 4 || s->cert[0] != 0x30) return CKR_DEVICE_ERROR;
    s->cert_len = len;
    s->cert_loaded = 1;
    parse_cert_metadata(s);
    return CKR_OK;
}

static rocei_session_t *find_session(CK_SESSION_HANDLE handle) {
    for (size_t i = 0; i < ROCEI_MAX_SESSIONS; i++) {
        if (g_sessions[i].in_use && g_sessions[i].handle == handle)
            return &g_sessions[i];
    }
    return NULL;
}

static void clear_session(rocei_session_t *s) {
    if (s->sign_buf) {
        memset(s->sign_buf, 0, s->sign_cap);
        free(s->sign_buf);
    }
    memset(s->pin_padded, 0, sizeof(s->pin_padded));
    if (s->card) SCardDisconnect(s->card, SCARD_LEAVE_CARD);
    if (s->ctx) SCardReleaseContext(s->ctx);
    memset(s, 0, sizeof(*s));
}

static CK_RV set_attr(CK_ATTRIBUTE_PTR attr, const void *value, CK_ULONG value_len) {
    if (!attr) return CKR_ARGUMENTS_BAD;
    if (!attr->pValue) {
        attr->ulValueLen = value_len;
        return CKR_OK;
    }
    if (attr->ulValueLen < value_len) {
        attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
        return CKR_BUFFER_TOO_SMALL;
    }
    if (value_len > 0 && value) memcpy(attr->pValue, value, value_len);
    attr->ulValueLen = value_len;
    return CKR_OK;
}

static CK_RV set_attr_bool(CK_ATTRIBUTE_PTR attr, CK_BBOOL value) {
    return set_attr(attr, &value, (CK_ULONG)sizeof(value));
}

static CK_RV object_attribute(rocei_session_t *s, CK_OBJECT_HANDLE object,
                              CK_ATTRIBUTE_PTR attr) {
    CK_OBJECT_CLASS cls;
    CK_KEY_TYPE key_type;
    CK_CERTIFICATE_TYPE cert_type;
    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;

    switch (object) {
    case ROCEI_CERT_HANDLE:
        switch (attr->type) {
        case CKA_CLASS:
            cls = CKO_CERTIFICATE;
            return set_attr(attr, &cls, sizeof(cls));
        case CKA_TOKEN: return set_attr_bool(attr, ck_true);
        case CKA_PRIVATE: return set_attr_bool(attr, ck_false);
        case CKA_MODIFIABLE: return set_attr_bool(attr, ck_false);
        case CKA_LABEL: return set_attr(attr, CERT_LABEL, sizeof(CERT_LABEL) - 1);
        case CKA_ID: return set_attr(attr, ROCEI_OBJECT_ID, sizeof(ROCEI_OBJECT_ID));
        case CKA_CERTIFICATE_TYPE:
            cert_type = CKC_X_509;
            return set_attr(attr, &cert_type, sizeof(cert_type));
        case CKA_VALUE:
            if (load_certificate(s) != CKR_OK) return CKR_DEVICE_ERROR;
            return set_attr(attr, s->cert, (CK_ULONG)s->cert_len);
        case CKA_SUBJECT:
            if (load_certificate(s) != CKR_OK) return CKR_DEVICE_ERROR;
            return set_attr(attr, s->subject, (CK_ULONG)s->subject_len);
        case CKA_ISSUER:
            if (load_certificate(s) != CKR_OK) return CKR_DEVICE_ERROR;
            return set_attr(attr, s->issuer, (CK_ULONG)s->issuer_len);
        case CKA_SERIAL_NUMBER:
            if (load_certificate(s) != CKR_OK) return CKR_DEVICE_ERROR;
            return set_attr(attr, s->serial, (CK_ULONG)s->serial_len);
        case CKA_TRUSTED: return set_attr_bool(attr, ck_false);
        default:
            attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
            return CKR_ATTRIBUTE_TYPE_INVALID;
        }

    case ROCEI_PRIVATE_KEY_HANDLE:
        switch (attr->type) {
        case CKA_CLASS:
            cls = CKO_PRIVATE_KEY;
            return set_attr(attr, &cls, sizeof(cls));
        case CKA_TOKEN: return set_attr_bool(attr, ck_true);
        case CKA_PRIVATE: return set_attr_bool(attr, ck_true);
        case CKA_MODIFIABLE: return set_attr_bool(attr, ck_false);
        case CKA_LABEL: return set_attr(attr, PRIV_LABEL, sizeof(PRIV_LABEL) - 1);
        case CKA_ID: return set_attr(attr, ROCEI_OBJECT_ID, sizeof(ROCEI_OBJECT_ID));
        case CKA_KEY_TYPE:
            key_type = CKK_EC;
            return set_attr(attr, &key_type, sizeof(key_type));
        case CKA_SIGN: return set_attr_bool(attr, ck_true);
        case CKA_DECRYPT: return set_attr_bool(attr, ck_false);
        case CKA_SENSITIVE: return set_attr_bool(attr, ck_true);
        case CKA_EXTRACTABLE: return set_attr_bool(attr, ck_false);
        case CKA_ALWAYS_SENSITIVE: return set_attr_bool(attr, ck_true);
        case CKA_NEVER_EXTRACTABLE: return set_attr_bool(attr, ck_true);
        case CKA_ALWAYS_AUTHENTICATE: return set_attr_bool(attr, ck_false);
        case CKA_EC_PARAMS:
            (void)load_certificate(s);
            return set_attr(attr, s->ec_params_len ? s->ec_params : EC_PARAMS_PRIME256V1,
                            (CK_ULONG)(s->ec_params_len ? s->ec_params_len : sizeof(EC_PARAMS_PRIME256V1)));
        default:
            attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
            return CKR_ATTRIBUTE_TYPE_INVALID;
        }

    case ROCEI_PUBLIC_KEY_HANDLE:
        switch (attr->type) {
        case CKA_CLASS:
            cls = CKO_PUBLIC_KEY;
            return set_attr(attr, &cls, sizeof(cls));
        case CKA_TOKEN: return set_attr_bool(attr, ck_true);
        case CKA_PRIVATE: return set_attr_bool(attr, ck_false);
        case CKA_MODIFIABLE: return set_attr_bool(attr, ck_false);
        case CKA_LABEL: return set_attr(attr, PUB_LABEL, sizeof(PUB_LABEL) - 1);
        case CKA_ID: return set_attr(attr, ROCEI_OBJECT_ID, sizeof(ROCEI_OBJECT_ID));
        case CKA_KEY_TYPE:
            key_type = CKK_EC;
            return set_attr(attr, &key_type, sizeof(key_type));
        case CKA_VERIFY: return set_attr_bool(attr, ck_true);
        case CKA_EC_PARAMS:
            (void)load_certificate(s);
            return set_attr(attr, s->ec_params_len ? s->ec_params : EC_PARAMS_PRIME256V1,
                            (CK_ULONG)(s->ec_params_len ? s->ec_params_len : sizeof(EC_PARAMS_PRIME256V1)));
        case CKA_EC_POINT:
            if (load_certificate(s) != CKR_OK || s->ec_point_len == 0) {
                attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            return set_attr(attr, s->ec_point, (CK_ULONG)s->ec_point_len);
        default:
            attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
            return CKR_ATTRIBUTE_TYPE_INVALID;
        }

    default:
        return CKR_OBJECT_HANDLE_INVALID;
    }
}

static int attr_matches(rocei_session_t *s, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR attr) {
    uint8_t tmp[1024];
    CK_ATTRIBUTE probe = {.type = attr->type, .pValue = NULL_PTR, .ulValueLen = 0};
    CK_RV ckr = object_attribute(s, object, &probe);
    if (ckr != CKR_OK || probe.ulValueLen == CK_UNAVAILABLE_INFORMATION || probe.ulValueLen > sizeof(tmp))
        return 0;
    probe.pValue = tmp;
    ckr = object_attribute(s, object, &probe);
    if (ckr != CKR_OK) return 0;
    return probe.ulValueLen == attr->ulValueLen &&
           (probe.ulValueLen == 0 || memcmp(tmp, attr->pValue, probe.ulValueLen) == 0);
}

static int object_matches(rocei_session_t *s, CK_OBJECT_HANDLE object,
                          CK_ATTRIBUTE_PTR templ, CK_ULONG count) {
    for (CK_ULONG i = 0; i < count; i++) {
        if (!templ[i].pValue && templ[i].ulValueLen != 0) return 0;
        if (!attr_matches(s, object, &templ[i])) return 0;
    }
    return 1;
}

static void clear_pin_cache(rocei_session_t *s) {
    memset(s->pin_padded, 0, sizeof(s->pin_padded));
    s->pin_cached = 0;
    s->pin_app = ROCEI_APP_NONE;
    s->pin_ref = 0;
}

static CK_RV verify_status_to_ckr(uint16_t sw) {
    if (sw == 0x6983) return CKR_PIN_LOCKED;
    if ((sw & 0xFFF0) == 0x63C0) return CKR_PIN_INCORRECT;
    if (sw == 0x6982 || sw == 0x6985) return CKR_USER_NOT_LOGGED_IN;
    return CKR_PIN_INCORRECT;
}

static CK_RV send_verify_pin(rocei_session_t *s, uint8_t pin_ref,
                             const uint8_t padded[12], const char *debug_label) {
    uint8_t cmd[17] = {0x00,0x20,0x00,pin_ref,0x0C};
    memcpy(cmd + 5, padded, 12);

    uint8_t resp[258];
    size_t resp_len = sizeof(resp);
    CK_RV ckr = tx(s, cmd, sizeof(cmd), resp, &resp_len);
    memset(cmd, 0, sizeof(cmd));
    if (ckr != CKR_OK) return ckr;
    debug_sw(debug_label, resp, resp_len);
    return response_ok(resp, resp_len) ? CKR_OK : verify_status_to_ckr(response_sw(resp, resp_len));
}

static CK_RV reverify_cached_pin(rocei_session_t *s) {
    if (!s->pin_cached || s->pin_app != s->selected_app) return CKR_USER_NOT_LOGGED_IN;
    return send_verify_pin(s, s->pin_ref, s->pin_padded, "VERIFY PIN cached");
}

static CK_RV verify_pin(rocei_session_t *s, const uint8_t *pin, size_t pin_len) {
    if (pin_len < 4 || pin_len > 12) return CKR_PIN_INCORRECT;
    const char *pin_app = getenv("ROCEI_PIN_APP");
    int use_qscd = pin_app && strcasecmp(pin_app, "qscd") == 0;
    int use_pki = !use_qscd;
    const uint8_t *aid = use_pki ? AID_PKI : AID_QSCD;
    size_t aid_len = use_pki ? sizeof(AID_PKI) : sizeof(AID_QSCD);
    uint8_t pin_ref = read_env_u8("ROCEI_PIN_REF", use_qscd ? 0x8C : 0x05);
    uint8_t padded[12];
    memset(padded, 0xFF, sizeof(padded));
    memcpy(padded, pin, pin_len);

    CK_RV ckr = select_aid(s, aid, aid_len);
    if (ckr != CKR_OK) return ckr;

    ckr = send_verify_pin(s, pin_ref, padded, "VERIFY PIN");
    if (ckr == CKR_OK) {
        clear_pin_cache(s);
        s->pin_cached = 1;
        s->pin_app = use_qscd ? ROCEI_APP_QSCD : ROCEI_APP_PKI;
        s->pin_ref = pin_ref;
        memcpy(s->pin_padded, padded, sizeof(s->pin_padded));
    }
    memset(padded, 0, sizeof(padded));
    return ckr;
}

#define ROCEI_MAX_MSE_BODIES 160
#define ROCEI_MAX_MSE_BODY_LEN 10

static CK_RV send_mse_body_p2(rocei_session_t *s, const uint8_t *body, size_t body_len, uint8_t p2) {
    uint8_t cmd[5 + ROCEI_MAX_MSE_BODY_LEN] = {0x00,0x22,0x41,p2,(uint8_t)body_len};
    if (body_len > ROCEI_MAX_MSE_BODY_LEN) return CKR_ARGUMENTS_BAD;
    memcpy(cmd + 5, body, body_len);
    uint8_t resp[258];
    size_t resp_len = sizeof(resp);
    debug_hex("MSE body", body, body_len);
    CK_RV ckr = tx(s, cmd, 5 + body_len, resp, &resp_len);
    debug_sw("MSE SET", resp, resp_len);
    if (ckr != CKR_OK) return ckr;
    return response_ok(resp, resp_len) ? CKR_OK : CKR_DEVICE_ERROR;
}


static void add_mse_candidate(uint8_t bodies[ROCEI_MAX_MSE_BODIES][ROCEI_MAX_MSE_BODY_LEN],
                              size_t body_lens[ROCEI_MAX_MSE_BODIES],
                              size_t *body_count,
                              const uint8_t *body, size_t body_len) {
    if (body_len > ROCEI_MAX_MSE_BODY_LEN) return;
    for (size_t i = 0; i < *body_count; i++) {
        if (body_lens[i] == body_len && memcmp(bodies[i], body, body_len) == 0)
            return;
    }
    if (*body_count >= ROCEI_MAX_MSE_BODIES) return;
    memcpy(bodies[*body_count], body, body_len);
    body_lens[*body_count] = body_len;
    (*body_count)++;
}

static void add_short_mse(uint8_t bodies[ROCEI_MAX_MSE_BODIES][ROCEI_MAX_MSE_BODY_LEN],
                          size_t body_lens[ROCEI_MAX_MSE_BODIES],
                          size_t *body_count, uint8_t alg, uint8_t key_ref) {
    uint8_t body[] = {0x80,0x01,alg,0x84,0x01,key_ref};
    add_mse_candidate(bodies, body_lens, body_count, body, sizeof(body));
}

static void add_short_key_first_mse(uint8_t bodies[ROCEI_MAX_MSE_BODIES][ROCEI_MAX_MSE_BODY_LEN],
                                    size_t body_lens[ROCEI_MAX_MSE_BODIES],
                                    size_t *body_count, uint8_t alg, uint8_t key_ref) {
    uint8_t body[] = {0x84,0x01,key_ref,0x80,0x01,alg};
    add_mse_candidate(bodies, body_lens, body_count, body, sizeof(body));
}


static void add_long_mse(uint8_t bodies[ROCEI_MAX_MSE_BODIES][ROCEI_MAX_MSE_BODY_LEN],
                         size_t body_lens[ROCEI_MAX_MSE_BODIES],
                         size_t *body_count, uint32_t ref, uint8_t key_ref) {
    uint8_t body[] = {
        0x80,0x04,(uint8_t)(ref >> 24),(uint8_t)(ref >> 16),
        (uint8_t)(ref >> 8),(uint8_t)ref,0x84,0x01,key_ref
    };
    add_mse_candidate(bodies, body_lens, body_count, body, sizeof(body));
}

static uint8_t combicao_digest_alg(size_t data_len) {
    switch (data_len) {
        case 20: return 0x14; /* ECDSA with SHA-1 digest */
        case 28: return 0x34; /* ECDSA with SHA-224 digest */
        case 32: return 0x44; /* ECDSA with SHA-256 digest */
        case 48: return 0x54; /* ECDSA with SHA-384 digest */
        case 64: return 0x64; /* ECDSA with SHA-512 digest */
        default: return 0x04; /* raw ECDSA */
    }
}

static uint32_t iso_digest_alg_ref(size_t data_len) {
    switch (data_len) {
        case 20: return 0xFF110800UL;
        case 28: return 0xFF130800UL;
        case 32: return 0xFF140800UL;
        case 48: return 0xFF150800UL;
        case 64: return 0xFF160800UL;
        default: return 0xFF200800UL;
    }
}

static size_t ecdsa_component_len(size_t data_len) {
    size_t configured = (size_t)read_env_u16("ROCEI_ECDSA_BYTES", 0);
    if (configured == 32 || configured == 48 || configured == 66) return configured;
    (void)data_len;
    return 48; /* The Romanian Advanced Signature key is secp384r1. */
}

static int der_int_to_fixed(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_len) {
    while (src_len > 0 && *src == 0x00) {
        src++;
        src_len--;
    }
    if (src_len > dst_len) return 0;
    memset(dst, 0, dst_len);
    memcpy(dst + dst_len - src_len, src, src_len);
    return 1;
}

static CK_RV normalize_ecdsa_signature(const uint8_t *in, size_t in_len,
                                       uint8_t *out, CK_ULONG *out_len,
                                       size_t component_len) {
    size_t raw_len = component_len * 2;
    if (in_len == raw_len) {
        if (*out_len < raw_len) {
            *out_len = (CK_ULONG)raw_len;
            return CKR_BUFFER_TOO_SMALL;
        }
        memcpy(out, in, raw_len);
        *out_len = (CK_ULONG)raw_len;
        return CKR_OK;
    }

    tlv_t seq, r, sv;
    if (!parse_tlv(in, in_len, 0, &seq) || seq.tag != 0x30) return CKR_GENERAL_ERROR;
    if (!parse_tlv(in, in_len, seq.value, &r) || r.tag != 0x02) return CKR_GENERAL_ERROR;
    if (!parse_tlv(in, in_len, r.end, &sv) || sv.tag != 0x02) return CKR_GENERAL_ERROR;

    if (*out_len < raw_len) {
        *out_len = (CK_ULONG)raw_len;
        return CKR_BUFFER_TOO_SMALL;
    }
    if (!der_int_to_fixed(in + r.value, r.len, out, component_len)) return CKR_GENERAL_ERROR;
    if (!der_int_to_fixed(in + sv.value, sv.len, out + component_len, component_len)) return CKR_GENERAL_ERROR;
    *out_len = (CK_ULONG)raw_len;
    return CKR_OK;
}

static CK_RV card_sign(rocei_session_t *s, const uint8_t *data, size_t data_len,
                       uint8_t *signature, CK_ULONG *signature_len) {
    CK_RV ckr = CKR_OK;
    const char *sign_app = getenv("ROCEI_SIGN_APP");
    int use_qscd = sign_app && strcasecmp(sign_app, "qscd") == 0;
    int target_app = use_qscd ? ROCEI_APP_QSCD : ROCEI_APP_PKI;
    const uint8_t *target_aid = use_qscd ? AID_QSCD : AID_PKI;
    size_t target_aid_len = use_qscd ? sizeof(AID_QSCD) : sizeof(AID_PKI);
    if (s->selected_app != target_app) {
        ckr = select_aid(s, target_aid, target_aid_len);
        if (ckr != CKR_OK) return ckr;
    }

    uint16_t sign_path_fid = read_env_u16("ROCEI_SIGN_SELECT_FID", 0);
    if (sign_path_fid) {
        ckr = select_ef(s, sign_path_fid);
        if (ckr != CKR_OK && getenv("ROCEI_SIGN_SELECT_FID")) return ckr;
    }

    if (data_len > 255) return CKR_DATA_LEN_RANGE;
    uint8_t key_ref = read_env_u8("ROCEI_KEY_REF", 0x8E);
    uint8_t env_short_alg = read_env_u8("ROCEI_MSE_ALG", 0x00);
    uint32_t env_alg_ref = read_env_u32("ROCEI_MSE_ALG_REF", 0);
    uint8_t digest_alg = combicao_digest_alg(data_len);
    uint32_t digest_alg_ref = iso_digest_alg_ref(data_len);

    /* All plausible IAS ECC key refs to probe if the configured one fails.
     * 0x8E is first: confirmed working on Romanian eID (PKI Advanced Signature key). */
    static const uint8_t PROBE_KEY_REFS[] = {
        0x8E, 0x81, 0x90, 0x8F, 0x91,
        0x80, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D,
        0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    };

    uint8_t bodies[ROCEI_MAX_MSE_BODIES][ROCEI_MAX_MSE_BODY_LEN];
    size_t body_lens[ROCEI_MAX_MSE_BODIES];
    size_t body_count = 0;

    if (use_qscd) {
        /* Try configured/default key_ref with multiple alg variants first */
        add_short_mse(bodies, body_lens, &body_count, digest_alg, key_ref);
        add_short_mse(bodies, body_lens, &body_count, 0x04, key_ref);
        add_short_key_first_mse(bodies, body_lens, &body_count, 0x04, key_ref);
        add_short_key_first_mse(bodies, body_lens, &body_count, digest_alg, key_ref);
        add_long_mse(bodies, body_lens, &body_count, digest_alg_ref, key_ref);
        add_long_mse(bodies, body_lens, &body_count, 0xFF200800UL, key_ref);
        if (env_short_alg) add_short_mse(bodies, body_lens, &body_count, env_short_alg, key_ref);
        if (env_alg_ref) add_long_mse(bodies, body_lens, &body_count, env_alg_ref, key_ref);
        /* Probe all other key refs with raw ECDSA — the card tells us which one exists via PSO:CDS */
        for (size_t k = 0; k < sizeof(PROBE_KEY_REFS); k++) {
            if (PROBE_KEY_REFS[k] == key_ref) continue;
            add_short_mse(bodies, body_lens, &body_count, 0x04, PROBE_KEY_REFS[k]);
            add_short_mse(bodies, body_lens, &body_count, digest_alg, PROBE_KEY_REFS[k]);
        }
    } else {
        add_long_mse(bodies, body_lens, &body_count, 0xFF200800UL, key_ref);
        add_long_mse(bodies, body_lens, &body_count, digest_alg_ref, key_ref);
        if (env_alg_ref) add_long_mse(bodies, body_lens, &body_count, env_alg_ref, key_ref);
        add_short_mse(bodies, body_lens, &body_count, 0x04, key_ref);
        add_short_mse(bodies, body_lens, &body_count, digest_alg, key_ref);
        add_short_key_first_mse(bodies, body_lens, &body_count, 0x04, key_ref);
        add_short_key_first_mse(bodies, body_lens, &body_count, digest_alg, key_ref);
        if (env_short_alg) add_short_mse(bodies, body_lens, &body_count, env_short_alg, key_ref);
        /* Probe all other key refs in PKI applet too */
        for (size_t k = 0; k < sizeof(PROBE_KEY_REFS); k++) {
            if (PROBE_KEY_REFS[k] == key_ref) continue;
            add_short_mse(bodies, body_lens, &body_count, 0x04, PROBE_KEY_REFS[k]);
            add_short_mse(bodies, body_lens, &body_count, digest_alg, PROBE_KEY_REFS[k]);
        }
    }

    /* Internal Authenticate: MSE:SET P2=0xA4 + INS=0x88 (IDEMIA path for CKM_ECDSA) */
    uint8_t ia_cmd[5 + 255 + 1];
    ia_cmd[0] = 0x00; ia_cmd[1] = 0x88; ia_cmd[2] = 0x00; ia_cmd[3] = 0x00;
    ia_cmd[4] = (uint8_t)data_len;
    memcpy(ia_cmd + 5, data, data_len);
    ia_cmd[5 + data_len] = 0x00;

    /* PSO:CDS fallback: MSE:SET P2=0xB6 + INS=0x2A (QSCD/always-authenticate path) */
    uint8_t pso_cmd[5 + 255 + 1];
    pso_cmd[0] = 0x00; pso_cmd[1] = 0x2A; pso_cmd[2] = 0x9E; pso_cmd[3] = 0x9A;
    pso_cmd[4] = (uint8_t)data_len;
    memcpy(pso_cmd + 5, data, data_len);
    pso_cmd[5 + data_len] = 0x00;

    uint8_t resp[1024];
    uint16_t last_sw = 0;
    for (size_t i = 0; i < body_count; i++) {
        /* --- Primary attempt: Internal Authenticate (P2=0xA4) --- */
        ckr = send_mse_body_p2(s, bodies[i], body_lens[i], 0xA4);
        if (ckr != CKR_OK) goto try_pso;

        {
            size_t resp_len = sizeof(resp);
            ckr = tx(s, ia_cmd, 6 + data_len, resp, &resp_len);
            debug_sw("INT AUTH", resp, resp_len);
            if (ckr == CKR_OK && response_sw(resp, resp_len) == 0x6700) {
                resp_len = sizeof(resp);
                ckr = tx(s, ia_cmd, 5 + data_len, resp, &resp_len);
                debug_sw("INT AUTH no Le", resp, resp_len);
            }
            if (ckr != CKR_OK) goto try_pso;
            last_sw = response_sw(resp, resp_len);

            if (response_ok(resp, resp_len) && resp_len > 2) {
                if (getenv("ROCEI_DEBUG"))
                    fprintf(stderr, "rocei_pkcs11: INT AUTH succeeded key_ref=0x%02X body=%zu\n",
                            bodies[i][body_lens[i] - 1], i);
                size_t component_len = ecdsa_component_len(data_len);
                return normalize_ecdsa_signature(resp, resp_len - 2, signature, signature_len, component_len);
            }

            /* 6982/6985: card wants PIN — verify then retry IA */
            if ((last_sw == 0x6982 || last_sw == 0x6985) && s->pin_cached) {
                ckr = reverify_cached_pin(s);
                if (ckr != CKR_OK) return ckr;
                ckr = send_mse_body_p2(s, bodies[i], body_lens[i], 0xA4);
                if (ckr != CKR_OK) goto try_pso;
                resp_len = sizeof(resp);
                ckr = tx(s, ia_cmd, 6 + data_len, resp, &resp_len);
                debug_sw("INT AUTH after PIN", resp, resp_len);
                if (ckr == CKR_OK && response_sw(resp, resp_len) == 0x6700) {
                    resp_len = sizeof(resp);
                    ckr = tx(s, ia_cmd, 5 + data_len, resp, &resp_len);
                }
                if (ckr != CKR_OK) return ckr;
                last_sw = response_sw(resp, resp_len);
                if (response_ok(resp, resp_len) && resp_len > 2) {
                    size_t component_len = ecdsa_component_len(data_len);
                    return normalize_ecdsa_signature(resp, resp_len - 2, signature, signature_len, component_len);
                }
            }

            /* IA returned 6A88 (key not at this ref) — skip PSO for this body */
            if (last_sw == 0x6A88 || last_sw == 0x6A80) continue;
        }

try_pso:
        /* --- Fallback: PSO:CDS (P2=0xB6) for QSCD/always-authenticate keys --- */
        ckr = send_mse_body_p2(s, bodies[i], body_lens[i], 0xB6);
        if (ckr != CKR_OK) continue;

        {
            size_t resp_len = sizeof(resp);
            ckr = tx(s, pso_cmd, 6 + data_len, resp, &resp_len);
            debug_sw("PSO CDS", resp, resp_len);
            if (ckr == CKR_OK && response_sw(resp, resp_len) == 0x6700) {
                resp_len = sizeof(resp);
                ckr = tx(s, pso_cmd, 5 + data_len, resp, &resp_len);
                debug_sw("PSO CDS no Le", resp, resp_len);
            }
            if (ckr != CKR_OK) return ckr;
            last_sw = response_sw(resp, resp_len);

            if (response_ok(resp, resp_len) && resp_len > 2) {
                if (getenv("ROCEI_DEBUG"))
                    fprintf(stderr, "rocei_pkcs11: PSO CDS succeeded key_ref=0x%02X body=%zu\n",
                            bodies[i][body_lens[i] - 1], i);
                size_t component_len = ecdsa_component_len(data_len);
                return normalize_ecdsa_signature(resp, resp_len - 2, signature, signature_len, component_len);
            }

            /* 6982/6985: verify PIN then retry PSO */
            if ((last_sw == 0x6982 || last_sw == 0x6985) && s->pin_cached) {
                ckr = reverify_cached_pin(s);
                if (ckr != CKR_OK) return ckr;
                ckr = send_mse_body_p2(s, bodies[i], body_lens[i], 0xB6);
                if (ckr != CKR_OK) continue;
                resp_len = sizeof(resp);
                ckr = tx(s, pso_cmd, 6 + data_len, resp, &resp_len);
                debug_sw("PSO CDS after PIN", resp, resp_len);
                if (ckr == CKR_OK && response_sw(resp, resp_len) == 0x6700) {
                    resp_len = sizeof(resp);
                    ckr = tx(s, pso_cmd, 5 + data_len, resp, &resp_len);
                }
                if (ckr != CKR_OK) return ckr;
                last_sw = response_sw(resp, resp_len);
                if (response_ok(resp, resp_len) && resp_len > 2) {
                    size_t component_len = ecdsa_component_len(data_len);
                    return normalize_ecdsa_signature(resp, resp_len - 2, signature, signature_len, component_len);
                }
            }

            /* 6A88/6A80/6982/6985: keep probing other bodies; anything else: give up */
            if (last_sw != 0x6A88 && last_sw != 0x6A80 &&
                last_sw != 0x6982 && last_sw != 0x6985) break;
        }
    }

    if (last_sw == 0x6982 || last_sw == 0x6985) return CKR_USER_NOT_LOGGED_IN;
    return CKR_DEVICE_ERROR;
}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    (void)pInitArgs;
    pthread_mutex_lock(&g_lock);
    if (g_initialized) {
        pthread_mutex_unlock(&g_lock);
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    memset(g_sessions, 0, sizeof(g_sessions));
    g_initialized = 1;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    if (pReserved) return CKR_ARGUMENTS_BAD;
    pthread_mutex_lock(&g_lock);
    if (!g_initialized) {
        pthread_mutex_unlock(&g_lock);
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    for (size_t i = 0; i < ROCEI_MAX_SESSIONS; i++) {
        if (g_sessions[i].in_use) clear_session(&g_sessions[i]);
    }
    g_initialized = 0;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    copy_padded(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "rocei");
    copy_padded(pInfo->libraryDescription, sizeof(pInfo->libraryDescription), "Romanian eID PKCS11");
    pInfo->libraryVersion.major = 0;
    pInfo->libraryVersion.minor = 1;
    return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
    if (!pulCount) return CKR_ARGUMENTS_BAD;

    SCARDCONTEXT ctx;
    CK_RV ckr = establish_context(&ctx);
    if (ckr != CKR_OK) return ckr;

    char readers[4096];
    DWORD readers_len = sizeof(readers);
    LONG rv = SCardListReaders(ctx, NULL, readers, &readers_len);
    if (rv != SCARD_S_SUCCESS) {
        SCardReleaseContext(ctx);
        *pulCount = 0;
        return CKR_OK;
    }

    CK_SLOT_ID slots[64];
    CK_ULONG count = 0;
    CK_SLOT_ID idx = 0;
    const char *p = readers;
    while (*p && count < 64) {
        if (!tokenPresent || reader_has_rocei_card(p))
            slots[count++] = ROCEI_SLOT_BASE + idx;
        p += strlen(p) + 1;
        idx++;
    }
    SCardReleaseContext(ctx);

    if (!pSlotList) {
        *pulCount = count;
        return CKR_OK;
    }
    if (*pulCount < count) {
        *pulCount = count;
        return CKR_BUFFER_TOO_SMALL;
    }
    memcpy(pSlotList, slots, count * sizeof(CK_SLOT_ID));
    *pulCount = count;
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    char reader[512];
    CK_RV ckr = get_reader_name(slotID, reader, sizeof(reader));
    if (ckr != CKR_OK) return ckr;
    memset(pInfo, 0, sizeof(*pInfo));
    copy_padded(pInfo->slotDescription, sizeof(pInfo->slotDescription), reader);
    copy_padded(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "PC/SC");
    pInfo->flags = CKF_REMOVABLE_DEVICE;
    if (reader_has_rocei_card(reader)) pInfo->flags |= CKF_TOKEN_PRESENT;
    pInfo->hardwareVersion.major = 0;
    pInfo->hardwareVersion.minor = 1;
    pInfo->firmwareVersion.major = 0;
    pInfo->firmwareVersion.minor = 1;
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    char reader[512];
    CK_RV ckr = get_reader_name(slotID, reader, sizeof(reader));
    if (ckr != CKR_OK) return ckr;
    if (!reader_has_rocei_card(reader)) return CKR_TOKEN_NOT_PRESENT;

    memset(pInfo, 0, sizeof(*pInfo));
    copy_padded(pInfo->label, sizeof(pInfo->label), "Romanian eID");
    copy_padded(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "Romania");
    copy_padded(pInfo->model, sizeof(pInfo->model), "IAS ECC");
    copy_padded(pInfo->serialNumber, sizeof(pInfo->serialNumber), "unknown");
    pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | CKF_LOGIN_REQUIRED;
    pInfo->ulMaxSessionCount = ROCEI_MAX_SESSIONS;
    pInfo->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulMaxRwSessionCount = ROCEI_MAX_SESSIONS;
    pInfo->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulMaxPinLen = 12;
    pInfo->ulMinPinLen = 4;
    pInfo->hardwareVersion.major = 0;
    pInfo->hardwareVersion.minor = 1;
    pInfo->firmwareVersion.major = 0;
    pInfo->firmwareVersion.minor = 1;
    return CKR_OK;
}

static int is_ecdsa_mechanism(CK_MECHANISM_TYPE m) {
    return m == CKM_ECDSA || m == CKM_ECDSA_SHA1 || m == CKM_ECDSA_SHA224 ||
           m == CKM_ECDSA_SHA256 || m == CKM_ECDSA_SHA384 || m == CKM_ECDSA_SHA512;
}

static int hash_for_mechanism(CK_MECHANISM_TYPE mech, const uint8_t *data, size_t data_len,
                               uint8_t *hash_out, size_t *hash_len_out) {
    switch (mech) {
    case CKM_ECDSA_SHA1:
        CC_SHA1(data, (CC_LONG)data_len, hash_out);
        *hash_len_out = CC_SHA1_DIGEST_LENGTH;
        return 1;
    case CKM_ECDSA_SHA224:
        CC_SHA224(data, (CC_LONG)data_len, hash_out);
        *hash_len_out = CC_SHA224_DIGEST_LENGTH;
        return 1;
    case CKM_ECDSA_SHA256:
        CC_SHA256(data, (CC_LONG)data_len, hash_out);
        *hash_len_out = CC_SHA256_DIGEST_LENGTH;
        return 1;
    case CKM_ECDSA_SHA384:
        CC_SHA384(data, (CC_LONG)data_len, hash_out);
        *hash_len_out = CC_SHA384_DIGEST_LENGTH;
        return 1;
    case CKM_ECDSA_SHA512:
        CC_SHA512(data, (CC_LONG)data_len, hash_out);
        *hash_len_out = CC_SHA512_DIGEST_LENGTH;
        return 1;
    default:
        return 0;
    }
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList,
                         CK_ULONG_PTR pulCount) {
    if (!pulCount) return CKR_ARGUMENTS_BAD;
    char reader[512];
    CK_RV ckr = get_reader_name(slotID, reader, sizeof(reader));
    if (ckr != CKR_OK) return ckr;
    CK_MECHANISM_TYPE mechs[] = {
        CKM_ECDSA, CKM_ECDSA_SHA1, CKM_ECDSA_SHA224,
        CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512,
    };
    CK_ULONG n = sizeof(mechs) / sizeof(mechs[0]);
    if (!pMechanismList) {
        *pulCount = n;
        return CKR_OK;
    }
    if (*pulCount < n) {
        *pulCount = n;
        return CKR_BUFFER_TOO_SMALL;
    }
    memcpy(pMechanismList, mechs, n * sizeof(CK_MECHANISM_TYPE));
    *pulCount = n;
    return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                         CK_MECHANISM_INFO_PTR pInfo) {
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    char reader[512];
    CK_RV ckr = get_reader_name(slotID, reader, sizeof(reader));
    if (ckr != CKR_OK) return ckr;
    if (!is_ecdsa_mechanism(type)) return CKR_MECHANISM_INVALID;
    pInfo->ulMinKeySize = 256;
    pInfo->ulMaxKeySize = 521;
    pInfo->flags = CKF_HW | CKF_SIGN | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS;
    return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
    (void)pApplication;
    (void)Notify;
    if (!phSession) return CKR_ARGUMENTS_BAD;
    if ((flags & CKF_SERIAL_SESSION) == 0) return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

    pthread_mutex_lock(&g_lock);
    if (!g_initialized) {
        pthread_mutex_unlock(&g_lock);
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    rocei_session_t *slot = NULL;
    for (size_t i = 0; i < ROCEI_MAX_SESSIONS; i++) {
        if (!g_sessions[i].in_use) {
            slot = &g_sessions[i];
            break;
        }
    }
    if (!slot) {
        pthread_mutex_unlock(&g_lock);
        return CKR_SESSION_COUNT;
    }
    memset(slot, 0, sizeof(*slot));
    slot->in_use = 1;
    slot->handle = g_next_session++;
    slot->slot_id = slotID;
    slot->rw = (flags & CKF_RW_SESSION) != 0;
    memcpy(slot->ec_params, EC_PARAMS_PRIME256V1, sizeof(EC_PARAMS_PRIME256V1));
    slot->ec_params_len = sizeof(EC_PARAMS_PRIME256V1);
    CK_RV ckr = connect_session_card(slot);
    if (ckr != CKR_OK) {
        clear_session(slot);
        pthread_mutex_unlock(&g_lock);
        return ckr;
    }
    ckr = load_certificate(slot);
    if (ckr != CKR_OK) {
        slot->cert_attempted = 0;
        slot->selected_app = ROCEI_APP_NONE;
    }
    *phSession = slot->handle;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    pthread_mutex_lock(&g_lock);
    rocei_session_t *s = find_session(hSession);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    clear_session(s);
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
    pthread_mutex_lock(&g_lock);
    for (size_t i = 0; i < ROCEI_MAX_SESSIONS; i++) {
        if (g_sessions[i].in_use && g_sessions[i].slot_id == slotID)
            clear_session(&g_sessions[i]);
    }
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    pthread_mutex_lock(&g_lock);
    rocei_session_t *s = find_session(hSession);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    pInfo->slotID = s->slot_id;
    if (s->rw)
        pInfo->state = s->logged_in ? CKS_RW_USER_FUNCTIONS : CKS_RW_PUBLIC_SESSION;
    else
        pInfo->state = s->logged_in ? CKS_RO_USER_FUNCTIONS : CKS_RO_PUBLIC_SESSION;
    pInfo->flags = CKF_SERIAL_SESSION | (s->rw ? CKF_RW_SESSION : 0);
    pInfo->ulDeviceError = 0;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
              CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
    if (userType != CKU_USER) return CKR_USER_TYPE_INVALID;
    if (!pPin && ulPinLen != 0) return CKR_ARGUMENTS_BAD;
    pthread_mutex_lock(&g_lock);
    rocei_session_t *s = find_session(hSession);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->logged_in) {
        pthread_mutex_unlock(&g_lock);
        return CKR_USER_ALREADY_LOGGED_IN;
    }
    CK_RV ckr = verify_pin(s, pPin, ulPinLen);
    if (ckr == CKR_OK) s->logged_in = 1;
    pthread_mutex_unlock(&g_lock);
    return ckr;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
    pthread_mutex_lock(&g_lock);
    rocei_session_t *s = find_session(hSession);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    s->logged_in = 0;
    clear_pin_cache(s);
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                        CK_ULONG ulCount) {
    pthread_mutex_lock(&g_lock);
    rocei_session_t *s = find_session(hSession);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->search_active || s->sign_active) {
        pthread_mutex_unlock(&g_lock);
        return CKR_OPERATION_ACTIVE;
    }
    if (!pTemplate && ulCount != 0) {
        pthread_mutex_unlock(&g_lock);
        return CKR_ARGUMENTS_BAD;
    }

    CK_OBJECT_HANDLE objects[] = {ROCEI_CERT_HANDLE, ROCEI_PRIVATE_KEY_HANDLE, ROCEI_PUBLIC_KEY_HANDLE};
    s->search_count = 0;
    s->search_index = 0;
    for (size_t i = 0; i < sizeof(objects) / sizeof(objects[0]); i++) {
        if (object_matches(s, objects[i], pTemplate, ulCount))
            s->search_results[s->search_count++] = objects[i];
    }
    s->search_active = 1;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
                    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
    if (!phObject || !pulObjectCount) return CKR_ARGUMENTS_BAD;
    pthread_mutex_lock(&g_lock);
    rocei_session_t *s = find_session(hSession);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!s->search_active) {
        pthread_mutex_unlock(&g_lock);
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    CK_ULONG remaining = s->search_count - s->search_index;
    CK_ULONG n = remaining < ulMaxObjectCount ? remaining : ulMaxObjectCount;
    for (CK_ULONG i = 0; i < n; i++)
        phObject[i] = s->search_results[s->search_index + i];
    s->search_index += n;
    *pulObjectCount = n;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
    pthread_mutex_lock(&g_lock);
    rocei_session_t *s = find_session(hSession);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!s->search_active) {
        pthread_mutex_unlock(&g_lock);
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    s->search_active = 0;
    s->search_count = s->search_index = 0;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    if (!pTemplate && ulCount != 0) return CKR_ARGUMENTS_BAD;
    pthread_mutex_lock(&g_lock);
    rocei_session_t *s = find_session(hSession);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }

    CK_RV final_rv = CKR_OK;
    for (CK_ULONG i = 0; i < ulCount; i++) {
        CK_RV rv = object_attribute(s, hObject, &pTemplate[i]);
        if (rv == CKR_BUFFER_TOO_SMALL)
            final_rv = CKR_BUFFER_TOO_SMALL;
        else if (rv == CKR_ATTRIBUTE_TYPE_INVALID && final_rv == CKR_OK)
            final_rv = CKR_ATTRIBUTE_TYPE_INVALID;
        else if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
            pthread_mutex_unlock(&g_lock);
            return rv;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return final_rv;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                 CK_OBJECT_HANDLE hKey) {
    if (!pMechanism) return CKR_ARGUMENTS_BAD;
    if (!is_ecdsa_mechanism(pMechanism->mechanism)) return CKR_MECHANISM_INVALID;
    if (hKey != ROCEI_PRIVATE_KEY_HANDLE) return CKR_KEY_HANDLE_INVALID;
    pthread_mutex_lock(&g_lock);
    rocei_session_t *s = find_session(hSession);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!s->logged_in) {
        pthread_mutex_unlock(&g_lock);
        return CKR_USER_NOT_LOGGED_IN;
    }
    if (s->sign_active || s->search_active) {
        pthread_mutex_unlock(&g_lock);
        return CKR_OPERATION_ACTIVE;
    }
    s->sign_active = 1;
    s->sign_mechanism = pMechanism->mechanism;
    s->sign_key = hKey;
    s->sign_len = 0;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
             CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    if (!pulSignatureLen) return CKR_ARGUMENTS_BAD;
    size_t component_len = ecdsa_component_len(ulDataLen);
    CK_ULONG required = (CK_ULONG)(component_len * 2);
    if (!pSignature) {
        *pulSignatureLen = required;
        return CKR_OK;
    }
    if (*pulSignatureLen < required) {
        *pulSignatureLen = required;
        return CKR_BUFFER_TOO_SMALL;
    }
    if (!pData && ulDataLen != 0) return CKR_ARGUMENTS_BAD;

    pthread_mutex_lock(&g_lock);
    rocei_session_t *s = find_session(hSession);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!s->sign_active) {
        pthread_mutex_unlock(&g_lock);
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    const uint8_t *sign_data = pData;
    size_t sign_data_len = (size_t)ulDataLen;
    uint8_t hash_buf[64];
    size_t hash_len = 0;
    if (s->sign_mechanism != CKM_ECDSA && pData) {
        if (!hash_for_mechanism(s->sign_mechanism, pData, sign_data_len, hash_buf, &hash_len)) {
            s->sign_active = 0;
            pthread_mutex_unlock(&g_lock);
            return CKR_MECHANISM_INVALID;
        }
        sign_data = hash_buf;
        sign_data_len = hash_len;
    }
    CK_RV ckr = card_sign(s, sign_data, sign_data_len, pSignature, pulSignatureLen);
    s->sign_active = 0;
    s->sign_len = 0;
    pthread_mutex_unlock(&g_lock);
    return ckr;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    if (!pPart && ulPartLen != 0) return CKR_ARGUMENTS_BAD;
    pthread_mutex_lock(&g_lock);
    rocei_session_t *s = find_session(hSession);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!s->sign_active) {
        pthread_mutex_unlock(&g_lock);
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (s->sign_len + ulPartLen > s->sign_cap) {
        size_t new_cap = s->sign_cap ? s->sign_cap * 2 : 128;
        while (new_cap < s->sign_len + ulPartLen) new_cap *= 2;
        uint8_t *p = realloc(s->sign_buf, new_cap);
        if (!p) {
            pthread_mutex_unlock(&g_lock);
            return CKR_HOST_MEMORY;
        }
        s->sign_buf = p;
        s->sign_cap = new_cap;
    }
    memcpy(s->sign_buf + s->sign_len, pPart, ulPartLen);
    s->sign_len += ulPartLen;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                  CK_ULONG_PTR pulSignatureLen) {
    if (!pulSignatureLen) return CKR_ARGUMENTS_BAD;
    pthread_mutex_lock(&g_lock);
    rocei_session_t *s = find_session(hSession);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!s->sign_active) {
        pthread_mutex_unlock(&g_lock);
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    size_t component_len = ecdsa_component_len(s->sign_len);
    CK_ULONG required = (CK_ULONG)(component_len * 2);
    if (!pSignature) {
        *pulSignatureLen = required;
        pthread_mutex_unlock(&g_lock);
        return CKR_OK;
    }
    if (*pulSignatureLen < required) {
        *pulSignatureLen = required;
        pthread_mutex_unlock(&g_lock);
        return CKR_BUFFER_TOO_SMALL;
    }
    const uint8_t *sign_data = s->sign_buf;
    size_t sign_data_len = s->sign_len;
    uint8_t hash_buf[64];
    size_t hash_len = 0;
    if (s->sign_mechanism != CKM_ECDSA && s->sign_buf && s->sign_len > 0) {
        if (!hash_for_mechanism(s->sign_mechanism, s->sign_buf, s->sign_len, hash_buf, &hash_len)) {
            s->sign_active = 0;
            if (s->sign_buf) memset(s->sign_buf, 0, s->sign_cap);
            s->sign_len = 0;
            pthread_mutex_unlock(&g_lock);
            return CKR_MECHANISM_INVALID;
        }
        sign_data = hash_buf;
        sign_data_len = hash_len;
    }
    CK_RV ckr = card_sign(s, sign_data, sign_data_len, pSignature, pulSignatureLen);
    s->sign_active = 0;
    if (s->sign_buf) memset(s->sign_buf, 0, s->sign_cap);
    s->sign_len = 0;
    pthread_mutex_unlock(&g_lock);
    return ckr;
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
                  CK_UTF8CHAR_PTR pLabel) {
    (void)slotID; (void)pPin; (void)ulPinLen; (void)pLabel; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
    (void)hSession; (void)pPin; (void)ulPinLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen,
               CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen) {
    (void)hSession; (void)pOldPin; (void)ulOldLen; (void)pNewPin; (void)ulNewLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
                          CK_ULONG_PTR pulOperationStateLen) {
    (void)hSession; (void)pOperationState; (void)pulOperationStateLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
                          CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey,
                          CK_OBJECT_HANDLE hAuthenticationKey) {
    (void)hSession; (void)pOperationState; (void)ulOperationStateLen; (void)hEncryptionKey; (void)hAuthenticationKey; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                     CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject) {
    (void)hSession; (void)pTemplate; (void)ulCount; (void)phObject; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                   CK_OBJECT_HANDLE_PTR phNewObject) {
    (void)hSession; (void)hObject; (void)pTemplate; (void)ulCount; (void)phNewObject; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
    (void)hSession; (void)hObject; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                      CK_ULONG_PTR pulSize) {
    (void)hSession; (void)hObject; (void)pulSize; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    (void)hSession; (void)hObject; (void)pTemplate; (void)ulCount; return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    (void)hSession; (void)pMechanism; (void)hKey; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
    (void)hSession; (void)pData; (void)ulDataLen; (void)pEncryptedData; (void)pulEncryptedDataLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                      CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
    (void)hSession; (void)pPart; (void)ulPartLen; (void)pEncryptedPart; (void)pulEncryptedPartLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
                     CK_ULONG_PTR pulLastEncryptedPartLen) {
    (void)hSession; (void)pLastEncryptedPart; (void)pulLastEncryptedPartLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    (void)hSession; (void)pMechanism; (void)hKey; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
                CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
    (void)hSession; (void)pEncryptedData; (void)ulEncryptedDataLen; (void)pData; (void)pulDataLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
    (void)hSession; (void)pEncryptedPart; (void)ulEncryptedPartLen; (void)pPart; (void)pulPartLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen) {
    (void)hSession; (void)pLastPart; (void)pulLastPartLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
    (void)hSession; (void)pMechanism; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
               CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
    (void)hSession; (void)pData; (void)ulDataLen; (void)pDigest; (void)pulDigestLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    (void)hSession; (void)pPart; (void)ulPartLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
    (void)hSession; (void)hKey; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
    (void)hSession; (void)pDigest; (void)pulDigestLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    (void)hSession; (void)pMechanism; (void)hKey; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    (void)hSession; (void)pData; (void)ulDataLen; (void)pSignature; (void)pulSignatureLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    (void)hSession; (void)pMechanism; (void)hKey; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
               CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
    (void)hSession; (void)pData; (void)ulDataLen; (void)pSignature; (void)ulSignatureLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    (void)hSession; (void)pPart; (void)ulPartLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
    (void)hSession; (void)pSignature; (void)ulSignatureLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    (void)hSession; (void)pMechanism; (void)hKey; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen,
                      CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
    (void)hSession; (void)pSignature; (void)ulSignatureLen; (void)pData; (void)pulDataLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                            CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
    (void)hSession; (void)pPart; (void)ulPartLen; (void)pEncryptedPart; (void)pulEncryptedPartLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                            CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
    (void)hSession; (void)pEncryptedPart; (void)ulEncryptedPartLen; (void)pPart; (void)pulPartLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                          CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
    (void)hSession; (void)pPart; (void)ulPartLen; (void)pEncryptedPart; (void)pulEncryptedPartLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
                            CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
    (void)hSession; (void)pEncryptedPart; (void)ulEncryptedPartLen; (void)pPart; (void)pulPartLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                    CK_OBJECT_HANDLE_PTR phKey) {
    (void)hSession; (void)pMechanism; (void)pTemplate; (void)ulCount; (void)phKey; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
                        CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
                        CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {
    (void)hSession; (void)pMechanism; (void)pPublicKeyTemplate; (void)ulPublicKeyAttributeCount;
    (void)pPrivateKeyTemplate; (void)ulPrivateKeyAttributeCount; (void)phPublicKey; (void)phPrivateKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
                CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
    (void)hSession; (void)pMechanism; (void)hWrappingKey; (void)hKey; (void)pWrappedKey; (void)pulWrappedKeyLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
                  CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
    (void)hSession; (void)pMechanism; (void)hUnwrappingKey; (void)pWrappedKey; (void)ulWrappedKeyLen;
    (void)pTemplate; (void)ulAttributeCount; (void)phKey; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
    (void)hSession; (void)pMechanism; (void)hBaseKey; (void)pTemplate; (void)ulAttributeCount; (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
    (void)hSession; (void)pSeed; (void)ulSeedLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen) {
    (void)hSession; (void)RandomData; (void)ulRandomLen; return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession) {
    (void)hSession; return CKR_FUNCTION_NOT_PARALLEL;
}
CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession) {
    (void)hSession; return CKR_FUNCTION_NOT_PARALLEL;
}
CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved) {
    (void)flags; (void)pSlot; (void)pReserved; return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_FUNCTION_LIST g_function_list = {
    .version = {2, 40},
    .C_Initialize = C_Initialize,
    .C_Finalize = C_Finalize,
    .C_GetInfo = C_GetInfo,
    .C_GetFunctionList = C_GetFunctionList,
    .C_GetSlotList = C_GetSlotList,
    .C_GetSlotInfo = C_GetSlotInfo,
    .C_GetTokenInfo = C_GetTokenInfo,
    .C_GetMechanismList = C_GetMechanismList,
    .C_GetMechanismInfo = C_GetMechanismInfo,
    .C_InitToken = C_InitToken,
    .C_InitPIN = C_InitPIN,
    .C_SetPIN = C_SetPIN,
    .C_OpenSession = C_OpenSession,
    .C_CloseSession = C_CloseSession,
    .C_CloseAllSessions = C_CloseAllSessions,
    .C_GetSessionInfo = C_GetSessionInfo,
    .C_GetOperationState = C_GetOperationState,
    .C_SetOperationState = C_SetOperationState,
    .C_Login = C_Login,
    .C_Logout = C_Logout,
    .C_CreateObject = C_CreateObject,
    .C_CopyObject = C_CopyObject,
    .C_DestroyObject = C_DestroyObject,
    .C_GetObjectSize = C_GetObjectSize,
    .C_GetAttributeValue = C_GetAttributeValue,
    .C_SetAttributeValue = C_SetAttributeValue,
    .C_FindObjectsInit = C_FindObjectsInit,
    .C_FindObjects = C_FindObjects,
    .C_FindObjectsFinal = C_FindObjectsFinal,
    .C_EncryptInit = C_EncryptInit,
    .C_Encrypt = C_Encrypt,
    .C_EncryptUpdate = C_EncryptUpdate,
    .C_EncryptFinal = C_EncryptFinal,
    .C_DecryptInit = C_DecryptInit,
    .C_Decrypt = C_Decrypt,
    .C_DecryptUpdate = C_DecryptUpdate,
    .C_DecryptFinal = C_DecryptFinal,
    .C_DigestInit = C_DigestInit,
    .C_Digest = C_Digest,
    .C_DigestUpdate = C_DigestUpdate,
    .C_DigestKey = C_DigestKey,
    .C_DigestFinal = C_DigestFinal,
    .C_SignInit = C_SignInit,
    .C_Sign = C_Sign,
    .C_SignUpdate = C_SignUpdate,
    .C_SignFinal = C_SignFinal,
    .C_SignRecoverInit = C_SignRecoverInit,
    .C_SignRecover = C_SignRecover,
    .C_VerifyInit = C_VerifyInit,
    .C_Verify = C_Verify,
    .C_VerifyUpdate = C_VerifyUpdate,
    .C_VerifyFinal = C_VerifyFinal,
    .C_VerifyRecoverInit = C_VerifyRecoverInit,
    .C_VerifyRecover = C_VerifyRecover,
    .C_DigestEncryptUpdate = C_DigestEncryptUpdate,
    .C_DecryptDigestUpdate = C_DecryptDigestUpdate,
    .C_SignEncryptUpdate = C_SignEncryptUpdate,
    .C_DecryptVerifyUpdate = C_DecryptVerifyUpdate,
    .C_GenerateKey = C_GenerateKey,
    .C_GenerateKeyPair = C_GenerateKeyPair,
    .C_WrapKey = C_WrapKey,
    .C_UnwrapKey = C_UnwrapKey,
    .C_DeriveKey = C_DeriveKey,
    .C_SeedRandom = C_SeedRandom,
    .C_GenerateRandom = C_GenerateRandom,
    .C_GetFunctionStatus = C_GetFunctionStatus,
    .C_CancelFunction = C_CancelFunction,
    .C_WaitForSlotEvent = C_WaitForSlotEvent,
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    if (!ppFunctionList) return CKR_ARGUMENTS_BAD;
    *ppFunctionList = &g_function_list;
    return CKR_OK;
}
