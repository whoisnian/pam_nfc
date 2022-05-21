#include "nfc.h"

SCARDCONTEXT _phContext;
SCARDHANDLE _phCard;
LPSTR _mszReaders;
LPSTR _szReader;
SCARD_IO_REQUEST _pioSendPci;

LONG nfc_connect(const char *readerName)
{
    LONG rv = 0;
    rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &_phContext);
    CHECK_SCARD_SUCCESS(rv);

    DWORD dwReaders = SCARD_AUTOALLOCATE;
    rv = SCardListReaders(_phContext, NULL, (LPSTR)&_mszReaders, &dwReaders);
    CHECK_SCARD_SUCCESS(rv);

    _szReader = _mszReaders;
    while (*_szReader && strstr(_szReader, readerName) == NULL)
        _szReader += strlen(_szReader) + 1;
    if (*_szReader == 0)
        return -1;

    DWORD dwActiveProtocol = 0;
    rv = SCardConnect(_phContext, _szReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &_phCard, &dwActiveProtocol);
    if (dwActiveProtocol == SCARD_PROTOCOL_T0)
        _pioSendPci = *SCARD_PCI_T0;
    else if (dwActiveProtocol == SCARD_PROTOCOL_T1)
        _pioSendPci = *SCARD_PCI_T1;
    return rv;
}

LONG nfc_disconnect()
{
    LONG rv = 0;
    rv = SCardDisconnect(_phCard, SCARD_LEAVE_CARD);
    CHECK_SCARD_SUCCESS(rv);
    rv = SCardFreeMemory(_phContext, _mszReaders);
    CHECK_SCARD_SUCCESS(rv);
    return SCardReleaseContext(_phContext);
}

LONG nfc_transmit(uint8_t *sbuf, size_t slen, uint8_t *rbuf, size_t *rlen)
{
    LONG rv = SCardTransmit(_phCard, &_pioSendPci, (LPCBYTE) sbuf, slen, NULL, rbuf, rlen);
    CHECK_SCARD_SUCCESS(rv);
    CHECK_SW_9000(rbuf, *rlen);
    return rv;
}

LONG nfc_read_uid(uint8_t *buf, size_t *len)
{
    LONG rv = SCardTransmit(_phCard, &_pioSendPci, (LPCBYTE) "\xFF\xCA\x00\x00\x00", 5, NULL, buf, len);
    CHECK_SCARD_SUCCESS(rv);
    CHECK_SW_9000(buf, *len);
    return rv;
}

LONG nfc_read_data(uint8_t *buf, size_t *len)
{
    LONG rv = 0;
    size_t ori = *len;
    rv = SCardTransmit(_phCard, &_pioSendPci, (LPCBYTE) "\xFF\x82\x00\x00\x06\x00\x00\x00\x00\x00\x00", 11, NULL, buf, len); // Load Authentication Keys
    CHECK_SCARD_SUCCESS(rv);
    CHECK_SW_9000(buf, *len);

    *len = ori;
    rv = SCardTransmit(_phCard, &_pioSendPci, (LPCBYTE) "\xFF\x86\x00\x00\x05\x01\x00\x04\x60\x00", 10, NULL, buf, len); // Authentication
    CHECK_SCARD_SUCCESS(rv);
    CHECK_SW_9000(buf, *len);

    size_t left = ori;
    rv = SCardTransmit(_phCard, &_pioSendPci, (LPCBYTE) "\xFF\xB0\x00\x04\x10", 5, NULL, buf, &left); // Read Binary Block 0x04
    CHECK_SCARD_SUCCESS(rv);
    CHECK_SW_9000(buf, left);
    *len = left - 2;

    left = ori - *len;
    rv = SCardTransmit(_phCard, &_pioSendPci, (LPCBYTE) "\xFF\xB0\x00\x05\x10", 5, NULL, buf + *len, &left); // Read Binary Block 0x05
    CHECK_SCARD_SUCCESS(rv);
    CHECK_SW_9000((buf + *len), left);
    *len += left - 2;

    left = ori - *len;
    rv = SCardTransmit(_phCard, &_pioSendPci, (LPCBYTE) "\xFF\xB0\x00\x06\x10", 5, NULL, buf + *len, &left); // Read Binary Block 0x06
    CHECK_SCARD_SUCCESS(rv);
    CHECK_SW_9000((buf + *len), left);
    *len += left - 2;

    return rv;
}
