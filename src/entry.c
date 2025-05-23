#include "internal.h"
#include "types.h"
#include <assert.h>
#include <limits.h>
#include <openssl/evp.h>
#include <passwand/passwand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static m_t *make_m_t(const char *mainpass) {
  m_t *const m = passwand_secure_malloc(sizeof(*m));
  if (m == NULL)
    return NULL;
  const size_t length = strlen(mainpass);
  m->data = passwand_secure_malloc(length);
  if (m->data == NULL && length > 0) {
    passwand_secure_free(m, sizeof(*m));
    return NULL;
  }
  if (length > 0)
    memcpy(m->data, mainpass, length);
  m->length = length;
  return m;
}

passwand_error_t passwand_entry_new(passwand_entry_t *e, const char *mainpass,
                                    const char *space, const char *key,
                                    const char *value, int work_factor) {

  assert(e != NULL);
  assert(mainpass != NULL);
  assert(space != NULL);
  assert(key != NULL);
  assert(value != NULL);

  *e = (passwand_entry_t){0};

  m_t *m = NULL;
  k_t *k = NULL;
  EVP_CIPHER_CTX *ctx = NULL;
  bool aes_encrypt_init_done = false;
  passwand_error_t rc = -1;

  // generate a random 8-byte salt
  uint8_t _salt[PW_SALT_LEN];
  rc = passwand_random_bytes(_salt, sizeof(_salt));
  if (rc != PW_OK)
    goto done;
  const salt_t salt = {
      .data = _salt,
      .length = sizeof(_salt),
  };

  // make an encryption key
  m = make_m_t(mainpass);
  if (m == NULL) {
    rc = PW_NO_MEM;
    goto done;
  }
  k = passwand_secure_malloc(sizeof(*k));
  if (k == NULL) {
    rc = PW_NO_MEM;
    goto done;
  }
  rc = make_key(m, &salt, work_factor, *k);
  if (rc != PW_OK)
    goto done;

  // generate a random 16-byte initialisation vector
  iv_t iv;
  rc = passwand_random_bytes(iv, sizeof(iv));
  if (rc != PW_OK)
    goto done;

  // setup an encryption context
  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    rc = PW_NO_MEM;
    goto done;
  }
  rc = aes_encrypt_init(*k, iv, ctx);
  if (rc != PW_OK)
    goto done;
  aes_encrypt_init_done = true;

  // now pack and encrypt each field
#define ENC(field)                                                             \
  do {                                                                         \
    pt_t *const p = passwand_secure_malloc(sizeof(*p));                        \
    if (p == NULL) {                                                           \
      rc = PW_NO_MEM;                                                          \
      goto done;                                                               \
    }                                                                          \
    const size_t length = strlen(field);                                       \
    p->data = passwand_secure_malloc(length);                                  \
    if (p->data == NULL && length > 0) {                                       \
      passwand_secure_free(p, sizeof(*p));                                     \
      rc = PW_NO_MEM;                                                          \
      goto done;                                                               \
    }                                                                          \
    if (length > 0) {                                                          \
      memcpy(p->data, field, length);                                          \
    }                                                                          \
    p->length = length;                                                        \
    ppt_t *const pp = passwand_secure_malloc(sizeof(*pp));                     \
    if (pp == NULL) {                                                          \
      passwand_secure_free(p->data, p->length);                                \
      passwand_secure_free(p, sizeof(*p));                                     \
      rc = PW_NO_MEM;                                                          \
      goto done;                                                               \
    }                                                                          \
    rc = pack_data(p, iv, pp);                                                 \
    passwand_secure_free(p->data, p->length);                                  \
    passwand_secure_free(p, sizeof(*p));                                       \
    if (rc != PW_OK) {                                                         \
      passwand_secure_free(pp, sizeof(*pp));                                   \
      goto done;                                                               \
    }                                                                          \
    ct_t c;                                                                    \
    rc = aes_encrypt(ctx, pp, &c);                                             \
    passwand_secure_free(pp->data, pp->length);                                \
    passwand_secure_free(pp, sizeof(*pp));                                     \
    if (rc != PW_OK) {                                                         \
      goto done;                                                               \
    }                                                                          \
    e->field = c.data;                                                         \
    e->field##_len = c.length;                                                 \
  } while (0)

  ENC(space);
  ENC(key);
  ENC(value);

#undef ENC

  // no longer need the encryption context
  rc = aes_encrypt_deinit(ctx);
  aes_encrypt_init_done = false;
  if (rc != PW_OK)
    goto done;

  // figure out what work factor make_key would have used
  if (work_factor == -1)
    work_factor = 14;
  assert(work_factor >= 10 && work_factor <= 31);
  e->work_factor = work_factor;

  // save the salt
  e->salt = malloc(sizeof(_salt));
  if (e->salt == NULL) {
    rc = PW_NO_MEM;
    goto done;
  }
  memcpy(e->salt, &_salt, sizeof(_salt));
  e->salt_len = sizeof(_salt);

  // save the IV
  e->iv = malloc(sizeof(iv));
  if (e->iv == NULL) {
    rc = PW_NO_MEM;
    goto done;
  }
  memcpy(e->iv, iv, sizeof(iv));
  e->iv_len = sizeof(iv);

  // set the HMAC
  rc = passwand_entry_set_mac(mainpass, e);
  if (rc != PW_OK)
    goto done;

  rc = PW_OK;

done:
  if (rc != PW_OK) {
    free(e->iv);
    free(e->salt);
    free(e->hmac_salt);
    free(e->hmac);
    free(e->value);
    free(e->key);
    free(e->space);
    *e = (passwand_entry_t){0};
  }
  if (aes_encrypt_init_done) {
    assert(ctx != NULL);
    (void)aes_encrypt_deinit(ctx);
  }
  if (ctx != NULL)
    EVP_CIPHER_CTX_free(ctx);
  if (k != NULL)
    passwand_secure_free(k, sizeof(*k));
  if (m != NULL) {
    passwand_secure_free(m->data, m->length);
    passwand_secure_free(m, sizeof(*m));
  }

  return rc;
}

static passwand_error_t get_mac(const char *mainpass, const passwand_entry_t *e,
                                mac_t *mac) {

  assert(e->hmac_salt != NULL);

  salt_t salt = {
      .data = e->hmac_salt,
      .length = e->hmac_salt_len,
  };

  // concatenate all the field data we will MAC
  if (SIZE_MAX - e->space_len < e->key_len)
    return PW_OVERFLOW;
  if (SIZE_MAX - e->space_len - e->key_len < e->value_len)
    return PW_OVERFLOW;
  if (SIZE_MAX - e->space_len - e->key_len - e->value_len < e->salt_len)
    return PW_OVERFLOW;
  if (SIZE_MAX - e->space_len - e->key_len - e->value_len - e->salt_len <
      e->iv_len)
    return PW_OVERFLOW;
  size_t len =
      e->space_len + e->key_len + e->value_len + e->salt_len + e->iv_len;
  uint8_t *_data = malloc(len);
  if (_data == NULL)
    return PW_NO_MEM;
  data_t data = {
      .data = _data,
      .length = len,
  };
  if (e->space_len > 0)
    memcpy(_data, e->space, e->space_len);
  _data += e->space_len;
  if (e->key_len > 0)
    memcpy(_data, e->key, e->key_len);
  _data += e->key_len;
  if (e->value_len > 0)
    memcpy(_data, e->value, e->value_len);
  _data += e->value_len;
  if (e->salt_len > 0)
    memcpy(_data, e->salt, e->salt_len);
  _data += e->salt_len;
  if (e->iv_len > 0)
    memcpy(_data, e->iv, e->iv_len);
  _data += e->iv_len;

  // now generate the MAC
  m_t *m = make_m_t(mainpass);
  if (m == NULL) {
    free(data.data);
    return PW_NO_MEM;
  }
  passwand_error_t err = hmac(m, &data, &salt, mac, e->work_factor);
  free(data.data);
  passwand_secure_free(m->data, m->length);
  passwand_secure_free(m, sizeof(*m));

  return err;
}

passwand_error_t passwand_entry_set_mac(const char *mainpass,
                                        passwand_entry_t *e) {

  assert(mainpass != NULL);
  assert(e != NULL);

  static const size_t HMAC_SALT_LEN = 8; // bytes

  free(e->hmac);
  e->hmac = NULL;

  if (e->hmac_salt == NULL) {
    // no existing salt; generate one now
    uint8_t *s = malloc(HMAC_SALT_LEN);
    if (s == NULL)
      return PW_NO_MEM;
    passwand_error_t err = passwand_random_bytes(s, HMAC_SALT_LEN);
    if (err != PW_OK) {
      free(s);
      return err;
    }
    e->hmac_salt = s;
    e->hmac_salt_len = HMAC_SALT_LEN;
  }

  mac_t mac;
  passwand_error_t err = get_mac(mainpass, e, &mac);
  if (err != PW_OK)
    return err;

  e->hmac = mac.data;
  e->hmac_len = mac.length;

  return PW_OK;
}

passwand_error_t passwand_entry_check_mac(const char *mainpass,
                                          const passwand_entry_t *e) {

  assert(mainpass != NULL);
  assert(e != NULL);

  if (e->hmac == NULL)
    return PW_BAD_HMAC;

  mac_t mac;
  passwand_error_t err = get_mac(mainpass, e, &mac);
  if (err != PW_OK)
    return err;

  bool r = mac.length == e->hmac_len &&
           (mac.length == 0 || memcmp(mac.data, e->hmac, mac.length) == 0);

  free(mac.data);

  return r ? PW_OK : PW_BAD_HMAC;
}

passwand_error_t
passwand_entry_do(const char *mainpass, const passwand_entry_t *e,
                  void (*action)(void *state, const char *space,
                                 const char *key, const char *value),
                  void *state) {

  assert(mainpass != NULL);
  assert(e != NULL);
  assert(action != NULL);

  // first check the MAC
  {
    passwand_error_t err = passwand_entry_check_mac(mainpass, e);
    if (err != PW_OK)
      return err;
  }

  m_t *m = NULL;
  k_t *k = NULL;
  EVP_CIPHER_CTX *ctx = NULL;
  bool aes_decrypt_init_done = false;
  char *space = NULL;
  char *key = NULL;
  char *value = NULL;
  passwand_error_t rc = -1;

  // generate the encryption key
  m = make_m_t(mainpass);
  if (m == NULL) {
    rc = PW_NO_MEM;
    goto done;
  }
  assert(e->salt != NULL);
  assert(e->salt_len > 0);
  salt_t salt = {
      .data = e->salt,
      .length = e->salt_len,
  };
  k = passwand_secure_malloc(sizeof(*k));
  if (k == NULL) {
    rc = PW_NO_MEM;
    goto done;
  }
  rc = make_key(m, &salt, e->work_factor, *k);
  if (rc != PW_OK)
    goto done;

  // extract the leading initialisation vector
  if (e->iv_len != PW_IV_LEN) {
    rc = PW_IV_MISMATCH;
    goto done;
  }
  iv_t iv;
  memcpy(iv, e->iv, e->iv_len);

  // setup a decryption context
  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    rc = PW_NO_MEM;
    goto done;
  }
  rc = aes_decrypt_init(*k, iv, ctx);
  if (rc != PW_OK)
    goto done;
  aes_decrypt_init_done = true;

#define DEC(field)                                                             \
  do {                                                                         \
    ct_t c = {                                                                 \
        .data = e->field,                                                      \
        .length = e->field##_len,                                              \
    };                                                                         \
    ppt_t *const pp = passwand_secure_malloc(sizeof(*pp));                     \
    if (pp == NULL) {                                                          \
      rc = PW_NO_MEM;                                                          \
      goto done;                                                               \
    }                                                                          \
    rc = aes_decrypt(ctx, &c, pp);                                             \
    if (rc != PW_OK) {                                                         \
      passwand_secure_free(pp, sizeof(*pp));                                   \
      goto done;                                                               \
    }                                                                          \
    pt_t *const p = passwand_secure_malloc(sizeof(*p));                        \
    if (p == NULL) {                                                           \
      passwand_secure_free(pp->data, pp->length);                              \
      passwand_secure_free(pp, sizeof(*pp));                                   \
      rc = PW_NO_MEM;                                                          \
      goto done;                                                               \
    }                                                                          \
    rc = unpack_data(pp, iv, p);                                               \
    passwand_secure_free(pp->data, pp->length);                                \
    passwand_secure_free(pp, sizeof(*pp));                                     \
    if (rc != PW_OK) {                                                         \
      passwand_secure_free(p, sizeof(*p));                                     \
      goto done;                                                               \
    }                                                                          \
    if (p->length > 0 && memchr(p->data, 0, p->length) != NULL) {              \
      /* The unpacked data contains a '\0' which will lead this string to be   \
       * misinterpreted later.                                                 \
       */                                                                      \
      passwand_secure_free(p->data, p->length);                                \
      passwand_secure_free(p, sizeof(*p));                                     \
      rc = PW_TRUNCATED;                                                       \
      goto done;                                                               \
    }                                                                          \
    if (SIZE_MAX - p->length < 1) {                                            \
      passwand_secure_free(p->data, p->length);                                \
      passwand_secure_free(p, sizeof(*p));                                     \
      rc = PW_OVERFLOW;                                                        \
      goto done;                                                               \
    }                                                                          \
    field = passwand_secure_malloc(p->length + 1);                             \
    if (field == NULL) {                                                       \
      passwand_secure_free(p->data, p->length);                                \
      passwand_secure_free(p, sizeof(*p));                                     \
      rc = PW_NO_MEM;                                                          \
      goto done;                                                               \
    }                                                                          \
    if (p->length > 0) {                                                       \
      memcpy(field, p->data, p->length);                                       \
    }                                                                          \
    field[p->length] = '\0';                                                   \
    passwand_secure_free(p->data, p->length);                                  \
    passwand_secure_free(p, sizeof(*p));                                       \
  } while (0)

  DEC(space);
  DEC(key);
  DEC(value);

#undef DEC

  // If we decrypted all the fields successfully, we can eagerly destroy the
  // decryption context. The advantage of this is that we can pass any error
  // back to the caller.
  rc = aes_decrypt_deinit(ctx);
  aes_decrypt_init_done = false;
  if (rc != PW_OK)
    goto done;

  assert(space != NULL);
  assert(key != NULL);
  assert(value != NULL);

  action(state, space, key, value);

  rc = PW_OK;

done:
  if (value != NULL)
    passwand_secure_free(value, strlen(value) + 1);
  if (key != NULL)
    passwand_secure_free(key, strlen(key) + 1);
  if (space != NULL)
    passwand_secure_free(space, strlen(space) + 1);
  if (aes_decrypt_init_done) {
    assert(ctx != NULL);
    (void)aes_decrypt_deinit(ctx);
  }
  if (ctx != NULL)
    EVP_CIPHER_CTX_free(ctx);
  if (k != NULL)
    passwand_secure_free(k, sizeof(*k));
  if (m != NULL) {
    passwand_secure_free(m->data, m->length);
    passwand_secure_free(m, sizeof(*m));
  }

  return rc;
}
