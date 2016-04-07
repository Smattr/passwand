#pragma once

#include <stdbool.h>

typedef struct {

    /* encrypted fields */
    char *space;
    char *key;
    char *value;

    /* hmac fields */
    char *hmac;
    char *hmac_salt;

    /* other core fields */
    char *salt;
    char *iv;

    /* fields that don't get exported */
    bool encrypted;
    unsigned int work_factor;

} passwand_entry_t;

/** Securely erase the memory backing a password.
 *
 * If input is the NULL pointer, this function is a no-op.
 *
 * @param s A NUL-terminated string
 * @return 0 on success
 */
int passwand_erase(char *s);
