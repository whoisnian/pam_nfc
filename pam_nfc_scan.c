/*************************************************************************
    > File Name: pam_nfc_scan.c
    > Author: nian
    > Blog: https://whoisnian.com
    > Mail: zhuchangbao1998@gmail.com
    > Created Time: 2022年05月08日 星期日 23时28分33秒
 ************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <crypt.h>

#include "nfc.h"

const char b16[16] = "0123456789abcdef";

void errorf(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    exit(1);
}

int main(int argc, const char **argv)
{
    if (argc != 2)
        errorf("Usage: %s <partial reader name>\n", argv[0]);

    if (0 != nfc_connect(argv[1]))
        errorf("Failed to connect to reader.\n");
    printf("reader=%s", argv[1]);

    uint8_t buf[256];
    size_t len = sizeof(buf);

    if (0 != nfc_read_uid(buf, &len))
        errorf("\nFailed to read card uid.\n");
    printf(" uid=");
    for (int i = 0; i < len - 2; i++)
        printf("%02x", buf[i]);

    len = sizeof(buf);
    if (0 != nfc_read_data(buf, &len))
        errorf("\nFailed to read card data.\n");

    if (0 != nfc_disconnect())
        errorf("\nFailed to disconnect.\n");

    printf(" user=%s", getlogin());

    char phrase[512];
    for (int i = 0; i < len; i++)
    {
        phrase[i * 2] = b16[buf[i] >> 4];
        phrase[i * 2 + 1] = b16[buf[i] & 0x0F];
    }
    phrase[len * 2] = 0;
    char *hash = crypt(phrase, "$1$pam_nfc$");
    printf(" pass=%s\n", hash + 11);
    return 0;
}
