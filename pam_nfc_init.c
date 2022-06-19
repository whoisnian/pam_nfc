/*************************************************************************
    > File Name: pam_nfc_init.c
    > Author: nian
    > Blog: https://whoisnian.com
    > Mail: zhuchangbao1998@gmail.com
    > Created Time: 2022年06月19日 星期日 22时27分17秒
 ************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <crypt.h>
#include <openssl/des.h>

#include "nfc.h"

#define H2B(x) ((x) <= '9' ? ((x) - '0') : ((x) - 'a' + 10))

void errorf(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    exit(1);
}

uint8_t *new_8_bytes_from_hex(const char *hex)
{
    uint8_t *buf = malloc(8);
    for (int i = 0; i < strlen(hex); i += 2)
    {
        buf[i / 2] = H2B(hex[i]) << 4;
        buf[i / 2] |= H2B(hex[i + 1]);
    }
    return buf;
}

uint8_t *new_8_bytes_from_rand()
{
    uint8_t *buf = malloc(8);
    for (int i = 0; i < 8; i++)
        buf[i] = rand() & 0xFF;
    return buf;
}

uint8_t factory_key[8] = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";

LONG auth_with_key(uint8_t *block_key)
{
    DES_key_schedule scheduleKey;
    DES_set_key_unchecked((const_DES_cblock *)(block_key), &scheduleKey);

    uint8_t rx[256];
    size_t rx_size = sizeof(rx);
    LONG rv = nfc_transmit((LPBYTE) "\x00\x84\x00\x00\x08", 5, rx, &rx_size);
    if (rv != 0)
        return rv;

    uint8_t tx[13] = "\x00\x82\x00\x00\x08";
    DES_ecb_encrypt((const_DES_cblock *)(rx), (DES_cblock *)(&tx[5]), &scheduleKey, DES_ENCRYPT);

    rx_size = sizeof(rx);
    return nfc_transmit((LPBYTE)tx, 13, rx, &rx_size);
}

LONG erase_with_key(uint8_t *block_key)
{
    uint8_t rx[256];
    size_t rx_size = sizeof(rx);
    LONG rv = nfc_transmit((LPBYTE) "\x80\x0E\x00\x00\x00", 5, rx, &rx_size);
    if (rv != 0)
        return rv;

    rx_size = sizeof(rx);
    rv = nfc_transmit((LPBYTE) "\x80\xE0\x00\x00\x07\x3F\x00\x50\x01\xF0\xFF\xFF", 12, rx, &rx_size);
    if (rv != 0)
        return rv;

    uint8_t tx[18] = "\x80\xD4\x01\x00\x0D\x39\xF0\xF0\xAA\x33";
    memcpy(tx + 10, block_key, 8);
    rx_size = sizeof(rx);
    return nfc_transmit((LPBYTE)tx, 18, rx, &rx_size);
}

LONG create_pam_df()
{
    uint8_t rx[256];
    size_t rx_size = sizeof(rx);
    LONG rv = nfc_transmit((LPBYTE) "\x80\xE0\x00\x01\x16\x38\x00\x00\xF0\xF0\x96\xFF\xFF\x4E\x43\x2E\x65\x43\x61\x72\x64\x2E\x44\x44\x46\x30\x31", 27, rx, &rx_size);
    if (rv != 0)
        return rv;

    rx_size = sizeof(rx);
    return nfc_transmit((LPBYTE) "\x00\xA4\x04\x00\x0E\x4E\x43\x2E\x65\x43\x61\x72\x64\x2E\x44\x44\x46\x30\x31", 19, rx, &rx_size);
}

LONG create_pam_ef()
{
    uint8_t rx[256];
    size_t rx_size = sizeof(rx);
    LONG rv = nfc_transmit((LPBYTE) "\x80\xE0\x00\x16\x07\x28\x00\x80\xF0\xF0\xFF\xFF", 12, rx, &rx_size);
    if (rv != 0)
        return rv;

    uint8_t tx[133] = "\x00\xD6\x96\x00\x80";
    for (int i = 0; i < 0x80; i++)
        tx[5 + i] = rand() & 0xFF;
    rx_size = sizeof(rx);
    return nfc_transmit((LPBYTE)tx, 133, rx, &rx_size);
}

int main(int argc, const char **argv)
{
    if (argc < 2)
        errorf("Usage: %s <partial reader name> [old_key] [new_key]\n", argv[0]);
    srand(time(NULL));
    
    uint8_t *old_key, *new_key;
    old_key = argc >= 3 ? new_8_bytes_from_hex(argv[2]) : factory_key;
    new_key = argc >= 4 ? new_8_bytes_from_hex(argv[3]) : new_8_bytes_from_rand();

    printf("old_key: ");
    for (int i = 0; i < 8; i++)
        printf("%02x", old_key[i]);
    printf("\nnew_key: ");
    for (int i = 0; i < 8; i++)
        printf("%02x", new_key[i]);
    printf("\n");

    if (0 != nfc_connect(argv[1]))
        errorf("Failed to connect to reader.\n");

    if (0 != auth_with_key(old_key))
        errorf("\nFailed to auth_with_old_key.\n");
    if (0 != erase_with_key(new_key))
        errorf("\nFailed to erase_with_new_key.\n");
    if (0 != create_pam_df())
        errorf("\nFailed to create_pam_df.\n");
    if (0 != auth_with_key(new_key))
        errorf("\nFailed to auth_with_new_key.\n");
    if (0 != create_pam_ef())
        errorf("\nFailed to create_pam_ef.\n");

    if (0 != nfc_disconnect())
        errorf("\nFailed to disconnect.\n");
    return 0;
}
