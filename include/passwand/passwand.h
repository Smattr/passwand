#pragma once

#include <errno.h>
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

typedef enum {
    PW_OK = 0,          /* no error */
    PW_IO = EIO,        /* I/O error */
    PW_NO_MEM = ENOMEM, /* out of memory */
    PW_OVERFLOW,        /* integer overflow */
    PW_BAD_KEY_SIZE,    /* incorrect key length */
    PW_BAD_IV_SIZE,     /* incorrect initialisation vector length */
    PW_BAD_WF,          /* incorrect work factor */
    PW_UNALIGNED,       /* unaligned data */
    PW_CRYPTO,          /* failure in underlying crypto library */
    PW_HEADER_MISMATCH, /* mismatched header value */
    PW_IV_MISMATCH,     /* mismatched initialisation vector */
    PW_TRUNCATED,       /* data was too short */
    PW_NOT_ENCRYPTED,   /* exfiltration attempted with unencrypted data */
    PW_BAD_JSON,        /* imported data did not conform to expected schema */
} passwand_error_t;

passwand_error_t passwand_entry_new(passwand_entry_t *e, const char *master, const char *space, const char *key, const char *value, int work_factor);

/** Securely erase the memory backing a password.
 *
 * If input is the NULL pointer, this function is a no-op.
 *
 * @param s A NUL-terminated string
 * @return PW_OK on success
 */
passwand_error_t passwand_erase(char *s);

/** Export a list of password entries to a file.
 *
 * @param path File to export to
 * @param entries An array of entries to export
 * @param entry_len The size of the array
 * @return PW_OK on success
 */
passwand_error_t passwand_export(const char *path, passwand_entry_t *entries, unsigned entry_len);

/** Import a list of password entries from a file.
 *
 * @param path File to import from
 * @param entries Output argument that will be set to the array of entries read
 * @param entry_len Output argument for the size of entries
 * @return PW_OK on success
 */
passwand_error_t passwand_import(const char *path, passwand_entry_t **entries, unsigned *entry_len);
