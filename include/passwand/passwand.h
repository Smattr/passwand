#pragma once

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef struct {

    /* encrypted fields */
    uint8_t *space;     size_t space_len;
    uint8_t *key;       size_t key_len;
    uint8_t *value;     size_t value_len;

    /* hmac fields */
    uint8_t *hmac;      size_t hmac_len;
    uint8_t *hmac_salt; size_t hmac_salt_len;

    /* other core fields */
    uint8_t *salt;      size_t salt_len;
    uint8_t *iv;        size_t iv_len;

    /* fields that don't get exported */
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
    PW_BAD_PADDING,     /* data was incorrectly padded */
    PW_BAD_JSON,        /* imported data did not conform to expected schema */
    PW_BAD_HMAC,        /* message failed authentication */
} passwand_error_t;

/** Translate an error code into a string
 *
 * @param err Error code
 * @return String representation of the code.
 */
const char *passwand_error(passwand_error_t err);

/* Various other ungrouped constants */
enum {
    PW_SALT_LEN = 8,    /* Length of salt added to the master passphrase */
    PW_IV_LEN = 16,     /* Length of initialisation vector */
};

/** Create a new entry
 *
 * @param[out] e      The entry to initialise
 * @param master      The master passphrase
 * @param space       The space field
 * @param key         The key field
 * @param value       The value field
 * @param work_factor The Scrypt work factor
 * @return            PW_OK on success
 */
passwand_error_t passwand_entry_new(passwand_entry_t *e, const char *master, const char *space,
    const char *key, const char *value, int work_factor);

/** Set the authentication code on an entry
 *
 * @param master The master passphrase
 * @param e      The entry whose authentication code to set
 * @return       PW_OK on success
 */
passwand_error_t passwand_entry_set_mac(const char *master, passwand_entry_t *e);

/** Authenticate an entry
 *
 * @param master Master passphrase
 * @param e      Entry to authenticate
 * @return       PW_OK on success
 */
passwand_error_t passwand_entry_check_mac(const char *master, const passwand_entry_t *e);

/** Perform an action with a decrypted entry
 *
 * This function does the work of decrypting the entry before calling the user action and then
 * securely cleaning up afterwards.
 *
 * @param master The master passphrase
 * @param e      The entry to decrypt
 * @param action The user action to perform
 * @param state  State passed to the user action
 * @return       PW_OK on success
 */
passwand_error_t passwand_entry_do(const char *master, passwand_entry_t *e,
    void (*action)(void *state, const char *space, const char *key, const char *value),
    void *state);

/** Securely erase the memory backing a password.
 *
 * If input is the NULL pointer, this function is a no-op.
 *
 * @param s Data to erase
 * @param len Length of data
 * @return PW_OK on success
 */
passwand_error_t passwand_erase(void *s, size_t len);

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

/** Allocate some secure memory.
 *
 * This function works similarly to malloc, but the backing memory is in a secure region.
 *
 * @param[out] p Address of allocated memory
 * @param size Number of bytes to allocate
 * @return 0 on success
 */
int passwand_secure_malloc(void **p, size_t size);

/** Free some secure memory.
 *
 * If you pass a pointer or size to this function that was not previously obtained from
 * passwand_secure_malloc, results are undefined.
 *
 * @param p Address of memory to free
 * @param size Number of bytes to free
 */
void passwand_secure_free(void *p, size_t size);

/** Print the current secure heap layout
 *
 * Only implemented for debugging purposes.
 *
 * @param f File to print to
 */
void passwand_secure_heap_print(FILE *f);
