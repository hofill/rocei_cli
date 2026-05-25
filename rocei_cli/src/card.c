#include "card.h"
#include "apdu.h"
#include <stdio.h>
#include <string.h>

int rocei_connect(rocei_card_t *card) {
    LONG rv;
    char readers_buf[4096];
    DWORD readers_len = sizeof(readers_buf);
    DWORD active_proto __attribute__((unused)) = 0;

    rv = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &card->ctx);
    if (rv != SCARD_S_SUCCESS) {
        fprintf(stderr, "SCardEstablishContext: 0x%08lX\n", (unsigned long)rv);
        return ROCEI_ERR_PCSC;
    }

    rv = SCardListReaders(card->ctx, NULL, readers_buf, &readers_len);
    if (rv != SCARD_S_SUCCESS || readers_len == 0) {
        fprintf(stderr, "No readers found\n");
        SCardReleaseContext(card->ctx);
        return ROCEI_ERR_NO_CARD;
    }

    /* Use first available reader (multi-string, first entry ends at \0) */
    memcpy(card->reader, readers_buf, sizeof(card->reader) - 1);
    card->reader[sizeof(card->reader) - 1] = '\0';

    rv = SCardConnect(card->ctx, card->reader,
                      SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                      &card->handle, &card->active_proto);
    active_proto = card->active_proto;
    if (rv != SCARD_S_SUCCESS) {
        fprintf(stderr, "SCardConnect: 0x%08lX\n", (unsigned long)rv);
        SCardReleaseContext(card->ctx);
        return ROCEI_ERR_NO_CARD;
    }

    /* Verify this is a Romanian eID by checking ATR */
    uint8_t atr[33];
    DWORD atr_len = sizeof(atr);
    DWORD state, proto;
    char rdr[256];
    DWORD rdr_len = sizeof(rdr);
    SCardStatus(card->handle, rdr, &rdr_len, &state, &proto, atr, &atr_len);

    if (!rocei_atr_matches(atr, atr_len)) {
        fprintf(stderr, "Card in reader is not a Romanian eID (unknown ATR)\n");
        SCardDisconnect(card->handle, SCARD_LEAVE_CARD);
        SCardReleaseContext(card->ctx);
        return ROCEI_ERR_NO_CARD;
    }

    return ROCEI_OK;
}

void rocei_disconnect(rocei_card_t *card) {
    SCardDisconnect(card->handle, SCARD_LEAVE_CARD);
    SCardReleaseContext(card->ctx);
}

int rocei_transmit(rocei_card_t *card,
                   const uint8_t *apdu, size_t apdu_len,
                   uint8_t *resp, size_t *resp_len) {
    DWORD recv_len = (DWORD)*resp_len;
    const SCARD_IO_REQUEST *pci =
        (card->active_proto == SCARD_PROTOCOL_T0) ? SCARD_PCI_T0 : SCARD_PCI_T1;
    LONG rv = SCardTransmit(card->handle,
                            pci,
                            apdu, (DWORD)apdu_len,
                            NULL, resp, &recv_len);
    if (rv != SCARD_S_SUCCESS) {
        fprintf(stderr, "SCardTransmit: 0x%08lX\n", (unsigned long)rv);
        return ROCEI_ERR_PCSC;
    }
    *resp_len = recv_len;

    /* Check SW1 SW2 */
    if (recv_len < 2) return ROCEI_ERR_APDU;
    uint8_t sw1 = resp[recv_len - 2];
    uint8_t sw2 = resp[recv_len - 1];
    if (sw1 == 0x90 && sw2 == 0x00) return ROCEI_OK;
    if (sw1 == 0x61) return ROCEI_OK;  /* more data */
    if (sw1 == 0x62 || sw1 == 0x63) return ROCEI_OK;  /* warning; caller checks SW */
    return ROCEI_ERR_APDU;
}
