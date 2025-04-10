#include "constants.h"
#include "internal.h"
#include "types.h"
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <passwand/passwand.h>
#include <stdint.h>
#include <stdlib.h>

passwand_error_t hmac(const m_t *mainkey, const data_t *data,
                      const salt_t *salt, mac_t *mac, int work_factor) {

  assert(mainkey != NULL);
  assert(data != NULL);
  assert(salt != NULL);
  assert(mac != NULL);

  k_t *k = NULL;
  uint8_t *mac_data = NULL;
  passwand_error_t rc = -1;

  k = passwand_secure_malloc(sizeof(*k));
  if (k == NULL) {
    rc = PW_NO_MEM;
    goto done;
  }
  rc = make_key(mainkey, salt, work_factor, *k);
  if (rc != PW_OK)
    goto done;

  const EVP_MD *sha512 = EVP_sha512();

  mac_data = malloc(EVP_MAX_MD_SIZE);
  if (mac_data == NULL) {
    rc = PW_NO_MEM;
    goto done;
  }
  unsigned md_len;
  unsigned char *r = HMAC(sha512, *k, AES_KEY_SIZE, data->data, data->length,
                          mac_data, &md_len);
  if (r == NULL) {
    rc = PW_CRYPTO;
    goto done;
  }

  mac->data = mac_data;
  mac_data = NULL;
  mac->length = md_len;
  rc = PW_OK;

done:
  free(mac_data);
  if (k != NULL)
    passwand_secure_free(k, sizeof(*k));

  return rc;
}
