/*************************************************************************
    > File Name: pam_nfc.c
    > Author: nian
    > Blog: https://whoisnian.com
    > Mail: zhuchangbao1998@gmail.com
    > Created Time: 2022年05月08日 星期日 23时28分33秒
 ************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <crypt.h>
#include <security/pam_modules.h>

#include "nfc.h"

const char b16[16] = "0123456789abcdef";

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const char *reader, *uid, *user, *pass;
    for (int i = 0; i < argc; i++)
    {
        if (strncmp(argv[i], "reader", 6) == 0)
            reader = argv[i] + 7;
        else if (strncmp(argv[i], "uid", 3) == 0)
            uid = argv[i] + 4;
        else if (strncmp(argv[i], "user", 4) == 0)
            user = argv[i] + 5;
        else if (strncmp(argv[i], "pass", 4) == 0)
            pass = argv[i] + 5;
    }

    const char *pam_user;
    if (PAM_SUCCESS != pam_get_user(pamh, &pam_user, NULL) || strcmp(pam_user, user) != 0)
        return PAM_USER_UNKNOWN;

    if (0 != nfc_connect(reader))
        return PAM_AUTHINFO_UNAVAIL;

    uint8_t buf[256];
    size_t len = sizeof(buf);

    if (0 != nfc_read_uid(buf, &len))
        return PAM_CRED_INSUFFICIENT;
    for (int i = 0; i < len - 2; i++)
        if (b16[buf[i] >> 4] != uid[2 * i] || b16[buf[i] & 0x0F] != uid[2 * i + 1])
            return PAM_CRED_INSUFFICIENT;

    len = sizeof(buf);
    if (0 != nfc_read_data(buf, &len))
        return PAM_CRED_INSUFFICIENT;

    if (0 != nfc_disconnect())
        return PAM_AUTHINFO_UNAVAIL;

    char phrase[512];
    for (int i = 0; i < len; i++)
    {
        phrase[i * 2] = b16[buf[i] >> 4];
        phrase[i * 2 + 1] = b16[buf[i] & 0x0F];
    }
    phrase[len * 2] = 0x00;
    char *hash = crypt(phrase, "$1$pam_nfc$"); // man 5 crypt
    if (strcmp(pass, hash + 11) == 0)
        return PAM_SUCCESS;
    return PAM_AUTH_ERR;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}
