#include <assert.h>
#include "encryption.h"
#include <passwand/passwand.h>
#include "random.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"

static void autowipe(void *p) {
    assert(p != NULL);
    k_t *k = p;
    if (k->data != NULL)
        passwand_erase(k->data, k->length);
}

passwand_error_t passwand_entry_new(passwand_entry_t *e, const char *master,
        const char *space, const char *key, const char *value,
        int work_factor) {
    assert(e != NULL);
    assert(master != NULL);
    assert(space != NULL);
    assert(key != NULL);
    assert(value != NULL);

    memset(e, 0, sizeof *e);

    /* Generate a random 8-byte salt. */
    uint8_t _salt[8];
    passwand_error_t err = random_bytes(_salt, sizeof _salt);
    if (err != PW_OK)
        return err;
    const salt_t salt = {
        .data = _salt,
        .length = sizeof _salt,
    };

    /* Make an encryption key. */
    const m_t m = {
        .data = (uint8_t*)master,
        .length = strlen(master),
    };
    k_t k __attribute__((cleanup(autowipe))) = { .data = NULL };
    err = make_key(&m, &salt, work_factor, &k);
    if (err != PW_OK)
        return err;

    /* Generate a random 16-byte initialisation vector. Note that we track this
     * as an integer because we're going to increment it while using AES in CTR
     * mode.
     */
    unsigned __int128 _iv;
    err = random_bytes((uint8_t*)&_iv, sizeof _iv);
    if (err != PW_OK)
        return err;

    /* Now pack and encrypt each field. */
#define ENC(field) \
    do { \
        pt_t p = { \
            .data = (uint8_t*)field, \
            .length = strlen(field), \
        }; \
        iv_t iv = { \
            .data = (uint8_t*)&_iv, \
            .length = sizeof _iv, \
        }; \
        ppt_t pp; \
        err = pack_data(&p, &iv, &pp); \
        if (err == PW_OK) { \
            ct_t c; \
            err = aes_encrypt(&k, &iv, &pp, &c); \
            free(pp.data); \
            if (err == PW_OK) { \
                e->field = c.data; \
                e->field##_len = c.length; \
            } \
        } \
        _iv++; \
    } while (0)

    ENC(space);
    if (err != PW_OK)
        return err;

    ENC(key);
    if (err != PW_OK) {
        free(e->space);
        return err;
    }

    ENC(value);
    if (err != PW_OK) {
        free(e->key);
        free(e->space);
        return err;
    }

#undef ENC

    /* Don't calculate the MAC at this point. We'll do that later before
     * exporting an entry.
     */

    /* Save the salt. */
    e->salt = malloc(sizeof _salt);
    if (e->salt == NULL) {
        free(e->value);
        free(e->key);
        free(e->space);
        return PW_NO_MEM;
    }
    memcpy(e->salt, &_salt, sizeof _salt);
    e->salt_len = sizeof _salt;

    /* Save the *initial* value of the IV. */
    _iv -= 3;
    e->iv = malloc(sizeof _iv);
    if (e->iv == NULL) {
        free(e->salt);
        free(e->value);
        free(e->key);
        free(e->space);
        return PW_NO_MEM;
    }
    memcpy(e->iv, &_iv, sizeof _iv);
    e->iv_len = sizeof _iv;

    e->encrypted = true;

    /* Figure out what work factor make_key would have used. */
    if (work_factor == -1)
        work_factor = 14;
    assert(work_factor >= 10 && work_factor <= 31);
    e->work_factor = work_factor;

    return PW_OK;
}
