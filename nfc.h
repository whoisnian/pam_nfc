#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <winscard.h>

#define CHECK_SCARD_SUCCESS(res) \
    if (res != SCARD_S_SUCCESS)  \
        return res;
#define CHECK_SW_9000(buf, len)                                  \
    if (len < 2 || buf[len - 2] != 0x90 || buf[len - 1] != 0x00) \
        return -1;

LONG nfc_connect(const char *readerName);
LONG nfc_disconnect();
LONG nfc_read_uid(uint8_t *buf, size_t *len);
LONG nfc_read_data(uint8_t *buf, size_t *len);
