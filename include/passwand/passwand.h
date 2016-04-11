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
    unsigned work_factor;

} passwand_entry_t;

/** Securely erase the memory backing a password.
 *
 * If input is the NULL pointer, this function is a no-op.
 *
 * @param s A NUL-terminated string
 * @return 0 on success
 */
int passwand_erase(char *s);

/** Export a list of password entries to a file.
 *
 * @param path File to export to
 * @param entries An array of entries to export
 * @param entry_len The size of the array
 * @return 0 on success
 */
int passwand_export(const char *path, passwand_entry_t *entries, unsigned entry_len);

/** Import a list of password entries from a file.
 *
 * @param path File to import from
 * @param entries Output argument that will be set to the array of entries read
 * @param entry_len Output argument for the size of entries
 * @return 0 on success
 */
int passwand_import(const char *path, passwand_entry_t **entries, unsigned *entry_len);
