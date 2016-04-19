#include <assert.h>
#include "auto.h"
#include "encryption.h"
#include "endian.h"
#include <limits.h>
#include <passwand/passwand.h>
#include "random.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"

passwand_error_t passwand_entry_new(passwand_entry_t *e, const char *master, const char *space,
        const char *key, const char *value, int work_factor) {

    assert(e != NULL);
    assert(master != NULL);
    assert(space != NULL);
    assert(key != NULL);
    assert(value != NULL);

    memset(e, 0, sizeof *e);

    /* Generate a random 8-byte salt. */
    uint8_t _salt[PW_SALT_LEN];
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
    AUTO_K_T(k);
    err = make_key(&m, &salt, work_factor, &k);
    if (err != PW_OK)
        return err;

    /* Generate a random 16-byte initialisation vector. Note that we track this as an integer
     * because we're going to increment it while using AES in CTR mode.
     */
    unsigned __int128 _iv;
    err = random_bytes((uint8_t*)&_iv, sizeof _iv);
    if (err != PW_OK)
        return err;

#define FREE(field) \
    do { \
        if (e->field != NULL) { \
            free(e->field); \
        } \
    } while (0)
#define CLEANUP() \
    do { \
        FREE(iv); \
        FREE(salt); \
        FREE(hmac_salt); \
        FREE(hmac); \
        FREE(value); \
        FREE(key); \
        FREE(space); \
    } while (0)

    /* Now pack and encrypt each field. */
#define ENC(field) \
    do { \
        pt_t *p; \
        if (passwand_secure_malloc((void**)&p, sizeof *p) != 0) { \
            CLEANUP(); \
            return PW_NO_MEM; \
        } \
        p->data = (uint8_t*)field; \
        p->length = strlen(field); \
        iv_t iv = { \
            .data = (uint8_t*)&_iv, \
            .length = sizeof _iv, \
        }; \
        ppt_t *pp; \
        if (passwand_secure_malloc((void**)&pp, sizeof *pp) != 0) { \
            passwand_secure_free(p, sizeof *p); \
            CLEANUP(); \
            return PW_NO_MEM; \
        } \
        err = pack_data(p, &iv, pp); \
        passwand_secure_free(p, sizeof *p); \
        if (err != PW_OK) { \
            passwand_secure_free(pp, sizeof *pp); \
            CLEANUP(); \
            return err; \
        } \
        ct_t c; \
        err = aes_encrypt(&k, &iv, pp, &c); \
        passwand_secure_free(pp->data, pp->length); \
        passwand_secure_free(pp, sizeof *pp); \
        if (err != PW_OK) { \
            CLEANUP(); \
            return err; \
        } \
        e->field = c.data; \
        e->field##_len = c.length; \
        _iv++; \
    } while (0)

    ENC(space);
    ENC(key);
    ENC(value);

#undef ENC

    /* Set the HMAC. */
    err = passwand_entry_set_mac(master, e);
    if (err != PW_OK) {
        CLEANUP();
        return PW_NO_MEM;
    }

    /* Save the salt. */
    e->salt = malloc(sizeof _salt);
    if (e->salt == NULL) {
        CLEANUP();
        return PW_NO_MEM;
    }
    memcpy(e->salt, &_salt, sizeof _salt);
    e->salt_len = sizeof _salt;

    /* Save the *initial* value of the IV. */
    _iv -= 3;
    unsigned __int128 _iv_le = htole128(_iv);
    e->iv = malloc(sizeof _iv_le);
    if (e->iv == NULL) {
        CLEANUP();
        return PW_NO_MEM;
    }
    memcpy(e->iv, &_iv_le, sizeof _iv_le);
    e->iv_len = sizeof _iv_le;

    e->encrypted = true;

    /* Figure out what work factor make_key would have used. */
    if (work_factor == -1)
        work_factor = 14;
    assert(work_factor >= 10 && work_factor <= 31);
    e->work_factor = work_factor;

    return PW_OK;

#undef CLEANUP
#undef FREE

}

static passwand_error_t get_mac(const char *master, passwand_entry_t *e, mac_t *mac) {

    if (!e->encrypted)
        return PW_NOT_ENCRYPTED;

    static const unsigned HMAC_SALT_LEN = 8; // bytes

    if (e->hmac == NULL) {
        /* No existing salt; generate one now. */
        uint8_t *s = malloc(HMAC_SALT_LEN);
        if (s == NULL)
            return PW_NO_MEM;
        passwand_error_t err = random_bytes(s, HMAC_SALT_LEN);
        if (err != PW_OK) {
            free(s);
            return err;
        }
        e->hmac_salt = s;
        e->hmac_salt_len = HMAC_SALT_LEN;
    }

    salt_t salt = {
        .data = e->hmac_salt,
        .length = e->hmac_salt_len,
    };

    /* Concatenate all the field data we'll MAC. */
    if (SIZE_MAX - e->space_len < e->key_len)
        return PW_OVERFLOW;
    if (SIZE_MAX - e->space_len - e->key_len < e->value_len)
        return PW_OVERFLOW;
    size_t len = e->space_len + e->key_len + e->value_len;
    uint8_t *_data = malloc(len);
    if (_data == NULL)
        return PW_NO_MEM;
    memcpy(_data, e->space, e->space_len);
    memcpy(_data + e->space_len, e->key, e->key_len);
    memcpy(_data + e->space_len + e->key_len, e->value, e->value_len);
    data_t data = {
        .data = _data,
        .length = len,
    };

    /* Now generate the MAC. */
    m_t m = {
        .data = (uint8_t*)master,
        .length = strlen(master),
    };
    passwand_error_t err = hmac(&m, &data, &salt, mac, e->work_factor);
    free(_data);

    return err;
}

passwand_error_t passwand_entry_set_mac(const char *master, passwand_entry_t *e) {

    assert(master != NULL);
    assert(e != NULL);

    if (e->hmac != NULL) {
        free(e->hmac);
        e->hmac = NULL;
    }
    if (e->hmac_salt != NULL) {
        free(e->hmac_salt);
        e->hmac_salt = NULL;
    }

    mac_t mac;
    passwand_error_t err = get_mac(master, e, &mac);
    if (err != PW_OK)
        return err;

    e->hmac = mac.data;
    e->hmac_len = mac.length;

    return PW_OK;
}

passwand_error_t passwand_entry_check_mac(const char *master, passwand_entry_t *e) {

    assert(master != NULL);
    assert(e != NULL);

    if (e->hmac == NULL)
        return PW_BAD_HMAC;

    mac_t mac;
    passwand_error_t err = get_mac(master, e, &mac);
    if (err != PW_OK)
        return err;

    bool r = mac.length == e->hmac_len &&
        memcmp(mac.data, e->hmac, mac.length) == 0;

    free(mac.data);

    return r ? PW_OK : PW_BAD_HMAC;
}

passwand_error_t passwand_entry_do(const char *master, passwand_entry_t *e,
        void (*action)(void *state, const char *space, const char *key, const char *value),
        void *state) {

    assert(master != NULL);
    assert(e != NULL);
    assert(action != NULL);

    /* First check the MAC. */
    passwand_error_t err = passwand_entry_check_mac(master, e);
    if (err != PW_OK)
        return err;

    /* Generate the encryption key. */
    m_t m = {
        .data = (uint8_t*)master,
        .length = strlen(master),
    };
    assert(e->salt != NULL);
    assert(e->salt_len > 0);
    salt_t salt = {
        .data = e->salt,
        .length = e->salt_len,
    };
    AUTO_K_T(k);
    err = make_key(&m, &salt, e->work_factor, &k);
    if (err != PW_OK)
        return err;

    /* Extract the leading initialisation vector. */
    if (e->iv_len != PW_IV_LEN)
        return PW_IV_MISMATCH;
    unsigned __int128 _iv_le;
    memcpy(&_iv_le, e->iv, e->iv_len);
    unsigned __int128 _iv = le128toh(_iv_le);

    AUTO_SECURE_STRING(space);
    AUTO_SECURE_STRING(key);
    AUTO_SECURE_STRING(value);

#define DEC(field) \
    do { \
        iv_t iv = { \
            .data = (uint8_t*)&_iv, \
            .length = sizeof _iv, \
        }; \
        ct_t c = { \
            .data = e->field, \
            .length = e->field##_len, \
        }; \
        AUTO_PPT_T(pp); \
        err = aes_decrypt(&k, &iv, &c, &pp); \
        if (err != PW_OK) { \
            return err; \
        } \
        AUTO_PT_T(p); \
        err = unpack_data(&pp, &iv, &p); \
        if (err != PW_OK) { \
            return err; \
        } \
        if (SIZE_MAX - p.length < 1) { \
            return PW_OVERFLOW; \
        } \
        field = malloc(p.length + 1); \
        if (field == NULL) { \
            return  PW_NO_MEM; \
        } \
        memcpy(field, p.data, p.length); \
        field[p.length] = '\0'; \
    } while (0)

    DEC(space);
    DEC(key);
    DEC(value);

#undef DEC

    action(state, space, key, value);

    return PW_OK;
}
