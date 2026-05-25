/*
 * rocei — Romanian eID CLI
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "compat.h"
#include "card.h"
#include "apdu.h"

#ifndef DEFAULT_SIGN_PY
#define DEFAULT_SIGN_PY "rocei_sign.py"
#endif

static void usage(void) {
    fprintf(stderr,
        "rocei — Romanian eID CLI\n\n"
        "usage:\n"
        "  rocei list\n"
        "  rocei read-cert                  dump signing cert (DER) to stdout\n"
        "  rocei read-id                    read personal data (4-digit PIN)\n"
        "  rocei sign [opts] <file>\n"
        "    PDF  → signed_<file>.pdf (embedded CAdES via rocei_sign.py)\n"
        "    other→ <file>.token  (JWT-like compact signed token)\n"
        "    opts:\n"
        "      --no-x5c     omit certificate from token header\n"
        "      --embed      embed file contents in payload instead of just hash\n"
        "  rocei sign-hash <hex>            sign raw hex hash, print base64url sig\n\n"
        "env: ROCEI_PIN, ROCEI_DATA_PIN, ROCEI_SIGN_PY\n"
    );
}

/* ----------------------------------------------------------------- base64url */

static const char B64URL[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static size_t b64url(const uint8_t *in, size_t in_len, char *out, size_t out_max) {
    size_t i = 0, o = 0;
    while (i < in_len && o + 4 < out_max) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < in_len) v |= (uint32_t)in[i+1] << 8;
        if (i + 2 < in_len) v |= (uint32_t)in[i+2];
        out[o++] = B64URL[(v >> 18) & 63];
        out[o++] = B64URL[(v >> 12) & 63];
        if (i + 1 < in_len) out[o++] = B64URL[(v >>  6) & 63];
        if (i + 2 < in_len) out[o++] = B64URL[ v        & 63];
        i += 3;
    }
    out[o] = '\0';
    return o;
}

/* ----------------------------------------------------------------- helpers */

static int hex_decode(const char *hex, uint8_t *out, size_t *out_len) {
    size_t hlen = strlen(hex);
    if (hlen % 2 || hlen / 2 > *out_len) return -1;
    for (size_t i = 0; i < hlen / 2; i++) {
        unsigned int b;
        if (sscanf(hex + 2*i, "%02x", &b) != 1 &&
            sscanf(hex + 2*i, "%02X", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    *out_len = hlen / 2;
    return 0;
}

static const char *get_env_pin(const char *env_var, const char *prompt_str) {
    const char *v = getenv(env_var);
    if (v && *v) return v;
    return getpass(prompt_str);
}

/* Chunked READ BINARY after EF is selected */
static size_t read_selected_ef(rocei_card_t *card, uint8_t *buf, size_t buf_max) {
    size_t offset = 0;
    while (offset < buf_max) {
        size_t want = buf_max - offset;
        if (want > 224) want = 224;
        uint8_t cmd[] = {0x00, 0xB0,
                         (uint8_t)(offset >> 8), (uint8_t)(offset & 0xFF),
                         (uint8_t)want};
        uint8_t resp[256]; size_t resp_len = sizeof(resp);
        rocei_transmit(card, cmd, sizeof(cmd), resp, &resp_len);
        if (resp_len < 2) break;
        uint8_t sw1 = resp[resp_len-2], sw2 = resp[resp_len-1];
        size_t chunk = resp_len - 2;
        if (chunk > 0) { memcpy(buf + offset, resp, chunk); offset += chunk; }
        if (sw1 == 0x62 && sw2 == 0x82) break;
        if (sw1 != 0x90) break;
        if (chunk < want) break;
    }
    return offset;
}

/* ------------------------------------------------------------ DG field table */

typedef struct { uint16_t dg; uint8_t ctx; const char *label; int is_date; } dg_field_t;
static const dg_field_t FIELDS[] = {
    {0x0101, 0x80, "Surname",               0},
    {0x0101, 0x81, "First name",            0},
    {0x0101, 0x82, "Sex",                   0},
    {0x0101, 0x83, "Date of birth",         1},
    {0x0101, 0x84, "Personal ID (CNP)",     0},
    {0x0101, 0x85, "Citizenship",           0},
    {0x0102, 0x81, "Place of birth",        0},
    {0x0104, 0x80, "Document number",       0},
    {0x0104, 0x81, "Expiry date",           1},
    {0x0104, 0x82, "Chip validity",         1},
    {0x0104, 0x83, "Issuing authority",     0},
    {0x0106, 0x80, "Address",               0},
    {0x0107, 0x81, "Doc validity from",     1},
    {0x0107, 0x82, "Doc validity to",       1},
    {0x0109, 0x80, "Birth ref",             0},
};

static const char *field_label(uint16_t dg, uint8_t ctx, int *is_date) {
    for (size_t i = 0; i < sizeof(FIELDS)/sizeof(FIELDS[0]); i++) {
        if (FIELDS[i].dg == dg && FIELDS[i].ctx == ctx) {
            if (is_date) *is_date = FIELDS[i].is_date;
            return FIELDS[i].label;
        }
    }
    return NULL;
}

static void print_utf8_value(const uint8_t *v, size_t vlen, int is_date) {
    if (is_date && vlen == 8) {
        int ok = 1;
        for (size_t k = 0; k < 8; k++) if (v[k] < '0' || v[k] > '9') { ok = 0; break; }
        if (ok) { printf("%.2s.%.2s.%.4s", v, v+2, v+4); return; }
    }
    /* Print UTF-8 string (Romanian diacritics are valid multi-byte UTF-8) */
    fwrite(v, 1, vlen, stdout);
}

/* Walk the TLV tree and print any context-specific primitive we recognise */
static void walk_tlv_print(uint16_t dg_id, const uint8_t *buf, size_t len) {
    struct { size_t pos; size_t end; } stk[32];
    int sp = 0;
    stk[0].pos = 0; stk[0].end = len;
    while (sp >= 0) {
        if (stk[sp].pos >= stk[sp].end) { sp--; continue; }
        size_t i = stk[sp].pos;
        uint8_t tag = buf[i++];
        if (i >= stk[sp].end) { sp--; continue; }
        size_t tlen;
        if      (buf[i] < 0x80)                        { tlen = buf[i++]; }
        else if (buf[i]==0x81 && i+1 < stk[sp].end)   { tlen = buf[i+1]; i+=2; }
        else if (buf[i]==0x82 && i+2 < stk[sp].end)   { tlen=((size_t)buf[i+1]<<8)|buf[i+2]; i+=3; }
        else { sp--; continue; }
        if (i + tlen > stk[sp].end) { sp--; continue; }
        stk[sp].pos = i + tlen;

        int constructed = (tag & 0x20) != 0;
        /* Context-specific primitive (0x80–0x9F) → potential string field */
        int is_ctx = (tag & 0xC0) == 0x80 && !constructed;
        if (is_ctx && tlen > 0) {
            int is_date = 0;
            const char *lbl = field_label(dg_id, tag, &is_date);
            if (lbl) {
                printf("  %-22s: ", lbl);
                print_utf8_value(buf + i, tlen, is_date);
                putchar('\n');
            }
        } else if (constructed && tlen > 0 && sp < 30) {
            stk[++sp].pos = i; stk[sp].end = i + tlen;
        }
    }
}

/* ---------------------------------------------------------------- commands */

static int cmd_list(rocei_card_t *card) {
    uint8_t buf[4096]; size_t len = sizeof(buf);
    if (rocei_read_ef(card, ROCEI_EF_SIGN_CERT, buf, &len) == ROCEI_OK)
        printf("Signing cert   EF 0x%04X : %zu bytes (DER)\n", ROCEI_EF_SIGN_CERT, len);
    printf("Key ref                  : 0x%02X  (ECDSA P-384, Internal Authenticate)\n", ROCEI_KEY_REF);
    printf("Signing PIN ref          : 0x%02X  (6-digit)\n", ROCEI_PIN_REF_SIGN);
    printf("Data PIN ref             : 0x%02X  (4-digit)\n", ROCEI_PIN_REF_DATA);
    return 0;
}

static int cmd_read_cert(rocei_card_t *card) {
    uint8_t buf[4096]; size_t len = sizeof(buf);
    if (rocei_read_ef(card, ROCEI_EF_SIGN_CERT, buf, &len) != ROCEI_OK) {
        fprintf(stderr, "Failed to read cert\n"); return 1;
    }
    fwrite(buf, 1, len, stdout);
    fprintf(stderr, "%zu DER bytes written to stdout\n", len);
    return 0;
}

static int cmd_read_id(rocei_card_t *card) {
    if (rocei_select_data_aid(card) != ROCEI_OK) {
        fprintf(stderr, "Failed to select DATA applet\n"); return 1;
    }
    const char *pin = get_env_pin("ROCEI_DATA_PIN", "Data PIN (4 digits): ");
    if (!pin || !*pin) return 1;

    /* Verify PIN once — do NOT re-select or re-verify inside the DG loop */
    if (rocei_verify_pin(card, ROCEI_PIN_REF_DATA, pin) != ROCEI_OK) {
        fprintf(stderr, "Data PIN verification failed\n"); return 1;
    }

    printf("\n");
    uint8_t buf[4096];
    int found = 0;
    for (uint16_t dg = ROCEI_DG_FIRST; dg <= ROCEI_DG_LAST; dg++) {
        uint8_t sel[] = {0x00,0xA4,0x02,0x04,0x02,(uint8_t)(dg>>8),(uint8_t)(dg&0xFF)};
        uint8_t resp[16]; size_t resp_len = sizeof(resp);
        rocei_transmit(card, sel, sizeof(sel), resp, &resp_len);
        if (resp_len < 2) continue;
        uint8_t sw1 = resp[resp_len-2];
        if (sw1 != 0x90 && sw1 != 0x61 && sw1 != 0x62) continue;

        size_t len = read_selected_ef(card, buf, sizeof(buf));
        if (len < 4) continue;

        walk_tlv_print(dg, buf, len);
        found++;
    }
    printf("\n");
    if (!found) fprintf(stderr, "No readable DGs\n");
    return found > 0 ? 0 : 1;
}

/* ------------------------------------------------------- token (JWT-style) */

typedef struct { int no_x5c; int embed_data; } sign_opts_t;

static int write_token(const char *token_path, const char *filename,
                       const uint8_t *file_data, size_t file_size,
                       const uint8_t *hash, size_t hash_len,
                       const uint8_t *cert, size_t cert_len,
                       const uint8_t *sig,  size_t sig_len,
                       const sign_opts_t *opts) {
    /* --- header --- */
    char header[16384];
    if (!opts->no_x5c && cert_len > 0) {
        char *b64c = malloc(cert_len * 2 + 16);
        if (!b64c) return 1;
        b64url(cert, cert_len, b64c, cert_len * 2 + 16);
        snprintf(header, sizeof(header),
                 "{\"alg\":\"ES384\",\"x5c\":[\"%s\"]}", b64c);
        free(b64c);
    } else {
        snprintf(header, sizeof(header), "{\"alg\":\"ES384\"}");
    }

    /* --- payload --- */
    char sha_hex[129] = {0};
    for (size_t i = 0; i < hash_len && i < 64; i++)
        sprintf(sha_hex + 2*i, "%02x", hash[i]);

    char *payload = NULL;
    if (opts->embed_data && file_data && file_size > 0) {
        char *b64d = malloc(file_size * 2 + 16);
        if (!b64d) return 1;
        b64url(file_data, file_size, b64d, file_size * 2 + 16);
        size_t psz = strlen(b64d) + 256;
        payload = malloc(psz);
        if (!payload) { free(b64d); return 1; }
        snprintf(payload, psz,
                 "{\"file\":\"%s\",\"data\":\"%s\",\"iat\":%ld}",
                 filename, b64d, (long)time(NULL));
        free(b64d);
    } else {
        payload = malloc(256);
        if (!payload) return 1;
        snprintf(payload, 256,
                 "{\"file\":\"%s\",\"sha256\":\"%s\",\"iat\":%ld}",
                 filename, sha_hex, (long)time(NULL));
    }

    /* --- encode + write --- */
    char *hdr_enc = malloc(strlen(header) * 2 + 16);
    char *pay_enc = malloc(strlen(payload) * 2 + 16);
    char *sig_enc = malloc(sig_len   * 2 + 16);
    if (!hdr_enc || !pay_enc || !sig_enc) { free(payload); free(hdr_enc); free(pay_enc); free(sig_enc); return 1; }

    b64url((uint8_t *)header,  strlen(header),  hdr_enc, strlen(header) * 2 + 16);
    b64url((uint8_t *)payload, strlen(payload), pay_enc, strlen(payload) * 2 + 16);
    b64url(sig, sig_len, sig_enc, sig_len * 2 + 16);

    FILE *f = fopen(token_path, "w");
    if (!f) { perror(token_path); free(payload); free(hdr_enc); free(pay_enc); free(sig_enc); return 1; }
    fprintf(f, "%s.%s.%s\n", hdr_enc, pay_enc, sig_enc);
    fclose(f);

    fprintf(stderr, "Token: %s\n", token_path);
    free(payload); free(hdr_enc); free(pay_enc); free(sig_enc);
    return 0;
}

static int cmd_sign(rocei_card_t *card, int argc, char **argv, sign_opts_t *opts) {
    /* find filename — first non-flag arg */
    const char *path = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--no-x5c")  == 0) { opts->no_x5c    = 1; continue; }
        if (strcmp(argv[i], "--embed")   == 0) { opts->embed_data = 1; continue; }
        path = argv[i];
    }
    if (!path) { fprintf(stderr, "sign: missing filename\n"); usage(); return 1; }

    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 1; }
    uint8_t magic[4] = {0};
    fread(magic, 1, 4, f);
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    fclose(f);

    if (memcmp(magic, "%PDF", 4) == 0) {
        const char *pin = get_env_pin("ROCEI_PIN", "Signing PIN: ");
        if (!pin || !*pin) return 1;
        const char *script = getenv("ROCEI_SIGN_PY");
        if (!script || !*script) script = DEFAULT_SIGN_PY;
        if (access(script, R_OK) != 0) {
            fprintf(stderr, "rocei_sign.py not found: %s\nSet ROCEI_SIGN_PY\n", script);
            return 1;
        }
        rocei_disconnect(card);
        const char *args[] = {"python3", script, path, "--pin", pin, NULL};
        rocei_execvp("python3", args);
        perror("exec python3"); return 1;
    }

    /* Read cert once */
    static uint8_t cert[4096]; size_t cert_len = sizeof(cert);
    if (rocei_read_ef(card, ROCEI_EF_SIGN_CERT, cert, &cert_len) != ROCEI_OK) cert_len = 0;

    /* Load file */
    f = fopen(path, "rb");
    if (!f) { perror(path); return 1; }
    uint8_t *data = malloc((size_t)fsz);
    if (!data) { fclose(f); return 1; }
    fread(data, 1, (size_t)fsz, f);
    fclose(f);

    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data, (CC_LONG)fsz, hash);

    const char *pin = get_env_pin("ROCEI_PIN", "Signing PIN: ");
    if (!pin || !*pin) { free(data); return 1; }

    if (rocei_verify_pin(card, ROCEI_PIN_REF_SIGN, pin) != ROCEI_OK) {
        fprintf(stderr, "PIN verification failed\n"); free(data); return 1;
    }
    if (rocei_mse_set_sign(card) != ROCEI_OK) {
        fprintf(stderr, "MSE:SET failed\n"); free(data); return 1;
    }

    uint8_t sig[256]; size_t sig_len = sizeof(sig);
    if (rocei_sign(card, hash, sizeof(hash), sig, &sig_len) != ROCEI_OK) {
        fprintf(stderr, "Signing failed\n"); free(data); return 1;
    }
    if (sig_len >= 2 && sig[sig_len-2] == 0x90 && sig[sig_len-1] == 0x00) sig_len -= 2;

    char token_path[4096];
    snprintf(token_path, sizeof(token_path), "%s.token", path);
    const char *name = strrchr(path, '/');
    name = name ? name + 1 : path;

    int rc = write_token(token_path, name,
                         opts->embed_data ? data : NULL, (size_t)fsz,
                         hash, sizeof(hash),
                         cert, cert_len,
                         sig, sig_len,
                         opts);
    free(data);
    return rc;
}

static int cmd_sign_hash(rocei_card_t *card, const char *hex) {
    uint8_t hash[64]; size_t hash_len = sizeof(hash);
    if (hex_decode(hex, hash, &hash_len) != 0) {
        fprintf(stderr, "Bad hex input\n"); return 1;
    }
    const char *pin = get_env_pin("ROCEI_PIN", "Signing PIN: ");
    if (!pin || !*pin) return 1;
    if (rocei_verify_pin(card, ROCEI_PIN_REF_SIGN, pin) != ROCEI_OK ||
        rocei_mse_set_sign(card) != ROCEI_OK) return 1;

    uint8_t sig[256]; size_t sig_len = sizeof(sig);
    if (rocei_sign(card, hash, hash_len, sig, &sig_len) != ROCEI_OK) return 1;
    if (sig_len >= 2 && sig[sig_len-2] == 0x90 && sig[sig_len-1] == 0x00) sig_len -= 2;

    char out[512]; b64url(sig, sig_len, out, sizeof(out));
    printf("%s\n", out);
    return 0;
}

/* -------------------------------------------------------------------- main */

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 1; }

    rocei_card_t card = {0};
    if (rocei_connect(&card) != ROCEI_OK) {
        fprintf(stderr, "No card found\n"); return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "read-id") == 0) {
        int rc = cmd_read_id(&card);
        rocei_disconnect(&card); return rc;
    }

    if (rocei_select_aid(&card) != ROCEI_OK) {
        fprintf(stderr, "Failed to select PKI applet\n");
        rocei_disconnect(&card); return 1;
    }

    int rc;
    if (strcmp(cmd, "list") == 0) {
        rc = cmd_list(&card);
    } else if (strcmp(cmd, "read-cert") == 0) {
        rc = cmd_read_cert(&card);
    } else if (strcmp(cmd, "sign") == 0 && argc >= 3) {
        sign_opts_t opts = {0};
        rc = cmd_sign(&card, argc - 2, argv + 2, &opts);
    } else if (strcmp(cmd, "sign-hash") == 0 && argc == 3) {
        rc = cmd_sign_hash(&card, argv[2]);
    } else {
        usage(); rc = 1;
    }

    rocei_disconnect(&card);
    return rc;
}
