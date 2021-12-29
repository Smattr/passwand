#include "auto.h"
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
  m_t *m;
  if (passwand_secure_malloc((void **)&m, sizeof(*m)) != 0)
    return NULL;
  m->data = (uint8_t *)mainpass;
  m->length = strlen(mainpass);
  return m;
}

static void unmake_m_t(void *p) {
  assert(p != NULL);
  m_t *m = *(m_t **)p;
  if (m != NULL)
    passwand_secure_free(m, sizeof(*m));
}
#define AUTO_M_T(name, mainpass)                                               \
  m_t *name __attribute__((cleanup(unmake_m_t))) = make_m_t(mainpass)

// auto-destruct infrastructure for use below
typedef struct {
  bool live;
  EVP_CIPHER_CTX *ctx;
} ctx_destructor_args_t;
static void ctx_destructor_decrypt(void *p) {
  assert(p != NULL);
  ctx_destructor_args_t *a = p;
  if (a->live) {
    (void)aes_decrypt_deinit(a->ctx);
    EVP_CIPHER_CTX_free(a->ctx);
  }
}

passwand_error_t passwand_entry_new(passwand_entry_t *e, const char *mainpass,
                                    const char *space, const char *key,
                                    const char *value, int work_factor) {

  assert(e != NULL);
  assert(mainpass != NULL);
  assert(space != NULL);
  assert(key != NULL);
  assert(value != NULL);

  memset(e, 0, sizeof(*e));

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
  k = make_k_t();
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
    pt_t *p;                                                                   \
    if (passwand_secure_malloc((void **)&p, sizeof(*p)) != 0) {                \
      rc = PW_NO_MEM;                                                          \
      goto done;                                                               \
    }                                                                          \
    p->data = (uint8_t *)field;                                                \
    p->length = strlen(field);                                                 \
    ppt_t *pp;                                                                 \
    if (passwand_secure_malloc((void **)&pp, sizeof(*pp)) != 0) {              \
      passwand_secure_free(p, sizeof(*p));                                     \
      rc = PW_NO_MEM;                                                          \
      goto done;                                                               \
    }                                                                          \
    rc = pack_data(p, iv, pp);                                                 \
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
    memset(e, 0, sizeof(*e));
  }
  if (aes_encrypt_init_done) {
    assert(ctx != NULL);
    (void)aes_encrypt_deinit(ctx);
  }
  if (ctx != NULL)
    EVP_CIPHER_CTX_free(ctx);
  if (k != NULL)
    passwand_secure_free(k, sizeof(*k));
  if (m != NULL)
    passwand_secure_free(m, sizeof(*m));

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
  AUTO_M_T(m, mainpass);
  if (m == NULL) {
    free(data.data);
    return PW_NO_MEM;
  }
  passwand_error_t err = hmac(m, &data, &salt, mac, e->work_factor);
  free(data.data);

  return err;
}

passwand_error_t passwand_entry_set_mac(const char *mainpass,
                                        passwand_entry_t *e) {

  assert(mainpass != NULL);
  assert(e != NULL);

  static const size_t HMAC_SALT_LEN = 8; // bytes

  if (e->hmac != NULL) {
    free(e->hmac);
    e->hmac = NULL;
  }
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

// auto-free functionality for use below
static void auto_secure_free(void *p) {
  assert(p != NULL);
  char *s = *(char **)p;
  if (s != NULL)
    passwand_secure_free(s, strlen(s) + 1);
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
  passwand_error_t err = passwand_entry_check_mac(mainpass, e);
  if (err != PW_OK)
    return err;

  // generate the encryption key
  AUTO_M_T(m, mainpass);
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
  err = make_key(m, &salt, e->work_factor, *k);
  if (err != PW_OK)
    return err;

  // extract the leading initialisation vector
  if (e->iv_len != PW_IV_LEN)
    return PW_IV_MISMATCH;
  iv_t iv;
  memcpy(iv, e->iv, e->iv_len);

  // setup a decryption context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL)
    return PW_NO_MEM;
  err = aes_decrypt_init(*k, iv, ctx);
  if (err != PW_OK) {
    EVP_CIPHER_CTX_free(ctx);
    return err;
  }

  // auto-destruct the context on scope exit
  ctx_destructor_args_t ctx_destruct
      __attribute__((cleanup(ctx_destructor_decrypt))) = {
          .live = true,
          .ctx = ctx,
      };

  char *space __attribute__((cleanup(auto_secure_free))) = NULL;
  char *key __attribute__((cleanup(auto_secure_free))) = NULL;
  char *value __attribute__((cleanup(auto_secure_free))) = NULL;

#define DEC(field)                                                             \
  do {                                                                         \
    ct_t c = {                                                                 \
        .data = e->field,                                                      \
        .length = e->field##_len,                                              \
    };                                                                         \
    ppt_t *pp;                                                                 \
    if (passwand_secure_malloc((void **)&pp, sizeof(*pp)) != 0) {              \
      return PW_NO_MEM;                                                        \
    }                                                                          \
    err = aes_decrypt(ctx, &c, pp);                                            \
    if (err != PW_OK) {                                                        \
      passwand_secure_free(pp, sizeof(*pp));                                   \
      return err;                                                              \
    }                                                                          \
    pt_t *p;                                                                   \
    if (passwand_secure_malloc((void **)&p, sizeof(*p)) != 0) {                \
      passwand_secure_free(pp->data, pp->length);                              \
      passwand_secure_free(pp, sizeof(*pp));                                   \
      return PW_NO_MEM;                                                        \
    }                                                                          \
    err = unpack_data(pp, iv, p);                                              \
    passwand_secure_free(pp->data, pp->length);                                \
    passwand_secure_free(pp, sizeof(*pp));                                     \
    if (err != PW_OK) {                                                        \
      passwand_secure_free(p, sizeof(*p));                                     \
      return err;                                                              \
    }                                                                          \
    if (p->length > 0 && memchr(p->data, 0, p->length) != NULL) {              \
      /* The unpacked data contains a '\0' which will lead this string to be   \
       * misinterpreted later.                                                 \
       */                                                                      \
      passwand_secure_free(p->data, p->length);                                \
      passwand_secure_free(p, sizeof(*p));                                     \
      return PW_TRUNCATED;                                                     \
    }                                                                          \
    if (SIZE_MAX - p->length < 1) {                                            \
      passwand_secure_free(p->data, p->length);                                \
      passwand_secure_free(p, sizeof(*p));                                     \
      return PW_OVERFLOW;                                                      \
    }                                                                          \
    if (passwand_secure_malloc((void **)&field, p->length + 1) != 0) {         \
      passwand_secure_free(p->data, p->length);                                \
      passwand_secure_free(p, sizeof(*p));                                     \
      return PW_NO_MEM;                                                        \
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
  err = aes_decrypt_deinit(ctx);
  EVP_CIPHER_CTX_free(ctx);
  ctx_destruct.live = false;
  if (err != PW_OK)
    return err;

  action(state, space, key, value);

  return PW_OK;
}
