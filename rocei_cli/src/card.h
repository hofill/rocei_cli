#pragma once

#ifdef __APPLE__
#  include <PCSC/winscard.h>
#  include <PCSC/wintypes.h>
#elif defined(_WIN32)
#  include <winscard.h>
#else
/* Linux / pcsclite */
#  include <PCSC/winscard.h>
#  include <PCSC/wintypes.h>
#endif

#include <stdint.h>
#include <stddef.h>

#define ROCEI_OK            0
#define ROCEI_ERR_NO_CARD  -1
#define ROCEI_ERR_PCSC     -2
#define ROCEI_ERR_APDU     -3
#define ROCEI_ERR_AUTH     -4
#define ROCEI_ERR_NOMEM    -5

typedef struct {
    SCARDCONTEXT ctx;
    SCARDHANDLE  handle;
    char         reader[256];
    DWORD        active_proto;
} rocei_card_t;

int  rocei_connect(rocei_card_t *card);
void rocei_disconnect(rocei_card_t *card);
int  rocei_transmit(rocei_card_t *card,
                    const uint8_t *apdu, size_t apdu_len,
                    uint8_t *resp, size_t *resp_len);
