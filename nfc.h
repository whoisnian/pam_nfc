#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <winscard.h>

LONG nfc_connect(const char *readerName);
LONG nfc_disconnect();
LONG nfc_read_uid(uint8_t *buf, size_t *len);
LONG nfc_read_data(uint8_t *buf, size_t *len);
