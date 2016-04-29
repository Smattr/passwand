#include <assert.h>
#include "auto.h"
#include "internal.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <passwand/passwand.h>
#include <stdlib.h>
#include "types.h"

passwand_error_t hmac(const k_t *key, const data_t *data, mac_t *mac) {

    assert(key != NULL);
    assert(data != NULL);

    const EVP_MD *sha512 = EVP_sha512();

    mac->data = malloc(EVP_MAX_MD_SIZE);
    if (mac->data == NULL)
        return PW_NO_MEM;
    unsigned md_len;
    unsigned char *r = HMAC(sha512, key->for_mac, sizeof(key->for_mac), data->data, data->length,
        mac->data, &md_len);
    if (r == NULL) {
        free(mac->data);
        return PW_CRYPTO;
    }

    mac->length = md_len;

    return PW_OK;
}
