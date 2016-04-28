#include <assert.h>
#include "auto.h"
#include "endian.h"
#include "internal.h"
#include <limits.h>
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"

static m_t *make_m_t(const char *master) {
    m_t *m;
    if (passwand_secure_malloc((void**)&m, sizeof *m) != 0)
        return NULL;
    m->data = (uint8_t*)master;
    m->length = strlen(master);
    return m;
}

static void unmake_m_t(void *p) {
    assert(p != NULL);
    m_t *m = *(m_t**)p;
    if (m != NULL)
        passwand_secure_free(m, sizeof *m);
}
#define AUTO_M_T(name, master) m_t *m __attribute__((cleanup(unmake_m_t))) = make_m_t(master)

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
    AUTO_M_T(m, master);
    if (m == NULL)
        return PW_NO_MEM;
    AUTO_K_T(k);
    if (k == NULL)
        return PW_NO_MEM;
    err = make_key(m, &salt, work_factor, k);
    if (err != PW_OK)
        return err;

    /* Generate a random 16-byte initialisation vector. Note that we track this as an integer
     * because we're going to increment it while using AES in CTR mode.
     */
    unsigned __int128 _iv;
    err = random_bytes(&_iv, sizeof _iv);
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
        EVP_CIPHER_CTX ctx; \
        err = aes_encrypt_init(k, &iv, &ctx); \
        if (err != PW_OK) { \
            passwand_secure_free(pp->data, pp->length); \
            passwand_secure_free(pp, sizeof *pp); \
            CLEANUP(); \
            return err; \
        } \
        err = aes_encrypt(&ctx, pp, &c); \
        passwand_secure_free(pp->data, pp->length); \
        passwand_secure_free(pp, sizeof *pp); \
        if (err != PW_OK) { \
            CLEANUP(); \
            return err; \
        } \
        err = aes_encrypt_deinit(&ctx); \
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

    /* Figure out what work factor make_key would have used. */
    if (work_factor == -1)
        work_factor = 14;
    assert(work_factor >= 10 && work_factor <= 31);
    e->work_factor = work_factor;

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

    /* Set the HMAC. */
    err = passwand_entry_set_mac(master, e);
    if (err != PW_OK) {
        CLEANUP();
        return PW_NO_MEM;
    }

    return PW_OK;

#undef CLEANUP
#undef FREE

}

static passwand_error_t get_mac(const char *master, const passwand_entry_t *e, mac_t *mac) {

    assert(e->hmac_salt != NULL);

    salt_t salt = {
        .data = e->hmac_salt,
        .length = e->hmac_salt_len,
    };

    /* Concatenate all the field data we'll MAC. */
    if (SIZE_MAX - e->space_len < e->key_len)
        return PW_OVERFLOW;
    if (SIZE_MAX - e->space_len - e->key_len < e->value_len)
        return PW_OVERFLOW;
    if (SIZE_MAX - e->space_len - e->key_len - e->value_len < e->salt_len)
        return PW_OVERFLOW;
    if (SIZE_MAX - e->space_len - e->key_len - e->value_len - e->salt_len < e->iv_len)
        return PW_OVERFLOW;
    size_t len = e->space_len + e->key_len + e->value_len + e->salt_len + e->iv_len;
    uint8_t *_data = malloc(len);
    if (_data == NULL)
        return PW_NO_MEM;
    data_t data = {
        .data = _data,
        .length = len,
    };
    memcpy(_data, e->space, e->space_len);
    _data += e->space_len;
    memcpy(_data, e->key, e->key_len);
    _data += e->key_len;
    memcpy(_data, e->value, e->value_len);
    _data += e->value_len;
    memcpy(_data, e->salt, e->salt_len);
    _data += e->salt_len;
    memcpy(_data, e->iv, e->iv_len);
    _data += e->iv_len;

    /* Now generate the MAC. */
    AUTO_M_T(m, master);
    if (m == NULL) {
        free(data.data);
        return PW_NO_MEM;
    }
    passwand_error_t err = hmac(m, &data, &salt, mac, e->work_factor);
    free(data.data);

    return err;
}

passwand_error_t passwand_entry_set_mac(const char *master, passwand_entry_t *e) {

    assert(master != NULL);
    assert(e != NULL);

    static const unsigned HMAC_SALT_LEN = 8; // bytes

    if (e->hmac != NULL) {
        free(e->hmac);
        e->hmac = NULL;
    }
    if (e->hmac_salt == NULL) {
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

    mac_t mac;
    passwand_error_t err = get_mac(master, e, &mac);
    if (err != PW_OK)
        return err;

    e->hmac = mac.data;
    e->hmac_len = mac.length;

    return PW_OK;
}

passwand_error_t passwand_entry_check_mac(const char *master, const passwand_entry_t *e) {

    assert(master != NULL);
    assert(e != NULL);

    if (e->hmac == NULL)
        return PW_BAD_HMAC;

    mac_t mac;
    passwand_error_t err = get_mac(master, e, &mac);
    if (err != PW_OK)
        return err;

    bool r = mac.length == e->hmac_len && memcmp(mac.data, e->hmac, mac.length) == 0;

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
    AUTO_M_T(m, master);
    if (m == NULL)
        return PW_NO_MEM;
    assert(e->salt != NULL);
    assert(e->salt_len > 0);
    salt_t salt = {
        .data = e->salt,
        .length = e->salt_len,
    };
    AUTO_K_T(k);
    if (k == NULL)
        return PW_NO_MEM;
    err = make_key(m, &salt, e->work_factor, k);
    if (err != PW_OK)
        return err;

    /* Extract the leading initialisation vector. */
    if (e->iv_len != PW_IV_LEN)
        return PW_IV_MISMATCH;
    unsigned __int128 _iv_le;
    memcpy(&_iv_le, e->iv, e->iv_len);
    unsigned __int128 _iv = le128toh(_iv_le);

    void auto_secure_free(void *p) {
        assert(p != NULL);
        char *s = *(char**)p;
        if (s != NULL)
            passwand_secure_free(s, strlen(s) + 1);
    }
    char *space __attribute__((cleanup(auto_secure_free))) = NULL;
    char *key __attribute__((cleanup(auto_secure_free))) = NULL;
    char *value __attribute__((cleanup(auto_secure_free))) = NULL;

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
        ppt_t *pp; \
        if (passwand_secure_malloc((void**)&pp, sizeof *pp) != 0) { \
            return PW_NO_MEM; \
        } \
        EVP_CIPHER_CTX ctx; \
        err = aes_decrypt_init(k, &iv, &ctx); \
        if (err != PW_OK) { \
            passwand_secure_free(pp, sizeof *pp); \
            return err; \
        } \
        err = aes_decrypt(&ctx, &c, pp); \
        if (err != PW_OK) { \
            passwand_secure_free(pp, sizeof *pp); \
            return err; \
        } \
        err = aes_decrypt_deinit(&ctx); \
        if (err != PW_OK) { \
            passwand_secure_free(pp->data, pp->length); \
            passwand_secure_free(pp, sizeof *pp); \
            return err; \
        } \
        pt_t *p; \
        if (passwand_secure_malloc((void**)&p, sizeof *p) != 0) { \
            passwand_secure_free(pp->data, pp->length); \
            passwand_secure_free(pp, sizeof *pp); \
            return PW_NO_MEM; \
        } \
        err = unpack_data(pp, &iv, p); \
        passwand_secure_free(pp->data, pp->length); \
        passwand_secure_free(pp, sizeof *pp); \
        if (err != PW_OK) { \
            passwand_secure_free(p, sizeof *p); \
            return err; \
        } \
        if (memchr(p->data, 0, p->length) != NULL) { \
            /* The unpacked data contains a '\0' which will lead this string to be misinterpreted
             * later.
             */ \
            passwand_secure_free(p->data, p->length); \
            passwand_secure_free(p, sizeof *p); \
            return PW_TRUNCATED; \
        } \
        if (SIZE_MAX - p->length < 1) { \
            passwand_secure_free(p->data, p->length); \
            passwand_secure_free(p, sizeof *p); \
            return PW_OVERFLOW; \
        } \
        if (passwand_secure_malloc((void**)&field, p->length + 1) != 0) { \
            passwand_secure_free(p->data, p->length); \
            passwand_secure_free(p, sizeof *p); \
            return PW_NO_MEM; \
        } \
        memcpy(field, p->data, p->length); \
        field[p->length] = '\0'; \
        passwand_secure_free(p->data, p->length); \
        passwand_secure_free(p, sizeof *p); \
        _iv++; \
    } while (0)

    DEC(space);
    DEC(key);
    DEC(value);

#undef DEC

    action(state, space, key, value);

    return PW_OK;
}
