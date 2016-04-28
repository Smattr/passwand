#include <assert.h>
#include "auto.h"
#include "internal.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <passwand/passwand.h>
#include <stdlib.h>
#include "types.h"

passwand_error_t hmac(const m_t *master, const data_t *data, const salt_t *salt, mac_t *mac,
        int work_factor) {

    assert(master != NULL);
    assert(data != NULL);
    assert(salt != NULL);
    assert(mac != NULL);

    AUTO_K_T(k);
    if (k == NULL)
        return PW_NO_MEM;
    passwand_error_t err = make_key(master, salt, work_factor, k);
    if (err != PW_OK)
        return err;

    const EVP_MD *sha512 = EVP_sha512();

    mac->data = malloc(EVP_MAX_MD_SIZE);
    if (mac->data == NULL)
        return PW_NO_MEM;
    unsigned md_len;
    unsigned char *r = HMAC(sha512, k->for_mac, sizeof(k->for_mac), data->data, data->length,
        mac->data, &md_len);
    if (r == NULL) {
        free(mac->data);
        return PW_CRYPTO;
    }

    mac->length = md_len;

    return PW_OK;
}
