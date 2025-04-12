#include "internal.h"
#include "types.h"
#include <assert.h>
#include <passwand/passwand.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __APPLE__
#include <libscrypt.h>

static int scrypt_kdf(const uint8_t *passwd, size_t passwdlen,
                      const uint8_t *salt, size_t saltlen, uint64_t N,
                      uint32_t r, uint32_t p, uint8_t *buf, size_t buflen) {
  return libscrypt_scrypt(passwd, passwdlen, salt, saltlen, N, r, p, buf,
                          buflen);
}
#else
#include <scrypt-kdf.h>
#endif

passwand_error_t make_key(const m_t *mainkey, const salt_t *salt,
                          int work_factor, k_t key) {

  assert(mainkey != NULL);
  assert(salt != NULL);
  assert(key != NULL);

  if (work_factor == -1)
    work_factor = 14; // default value

  if (work_factor < 10 || work_factor > 31)
    return PW_BAD_WF;

  static const uint32_t r = 8;
  static const uint32_t p = 1;

  if (scrypt_kdf(mainkey->data, mainkey->length, salt->data, salt->length,
                 ((uint64_t)1) << work_factor, r, p, key, AES_KEY_SIZE) != 0)
    return PW_CRYPTO;

  return PW_OK;
}
