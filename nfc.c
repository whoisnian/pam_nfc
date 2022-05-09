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
    if (rv != SCARD_S_SUCCESS)
        return rv;

    DWORD dwReaders = SCARD_AUTOALLOCATE;
    rv = SCardListReaders(_phContext, NULL, (LPSTR)&_mszReaders, &dwReaders);
    if (rv != SCARD_S_SUCCESS)
        return rv;

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
    if (rv != SCARD_S_SUCCESS)
        return rv;
    rv = SCardFreeMemory(_phContext, _mszReaders);
    if (rv != SCARD_S_SUCCESS)
        return rv;
    return SCardReleaseContext(_phContext);
}

LONG nfc_read_uid(uint8_t *buf, size_t *len)
{
    LONG rv = SCardTransmit(_phCard, &_pioSendPci, (LPCBYTE) "\xFF\xCA\x00\x00\x00", 5, NULL, buf, len);
    if (rv != SCARD_S_SUCCESS)
        return rv;
    if (*len < 2 || buf[*len - 2] != 0x90 || buf[*len - 1] != 0x00)
        return -1;
    return rv;
}

LONG nfc_read_data(uint8_t *buf, size_t *len)
{
    LONG rv = 0;
    size_t ori = *len;
    rv = SCardTransmit(_phCard, &_pioSendPci, (LPCBYTE) "\x00\xA4\x04\x00\x0E\x4E\x43\x2E\x65\x43\x61\x72\x64\x2E\x44\x44\x46\x30\x31", 19, NULL, buf, len);
    if (rv != SCARD_S_SUCCESS)
        return rv;
    if (*len < 2 || buf[*len - 2] != 0x90 || buf[*len - 1] != 0x00)
        return -1;

    *len = ori;
    rv = SCardTransmit(_phCard, &_pioSendPci, (LPCBYTE) "\x00\xB0\x96\x00\x00", 5, NULL, buf, len);
    if (rv != SCARD_S_SUCCESS)
        return rv;
    if (*len < 2 || buf[*len - 2] != 0x90 || buf[*len - 1] != 0x00)
        return -1;
    return rv;
}
