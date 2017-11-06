#include <assert.h>
#include "internal.h"
#include <crypto/crypto_scrypt.h>
#include <passwand/passwand.h>
#include <stddef.h>
#include <stdint.h>
#include "types.h"

passwand_error_t make_key(const m_t *master, const salt_t *salt, int work_factor, k_t key) {

    assert(master != NULL);
    assert(salt != NULL);
    assert(key != NULL);

    if (work_factor == -1)
        work_factor = 14; // default value

    if (work_factor < 10 || work_factor > 31)
        return PW_BAD_WF;

    static const uint32_t r = 8;
    static const uint32_t p = 1;

    if (crypto_scrypt(master->data, master->length, salt->data, salt->length,
            ((uint64_t)1) << work_factor, r, p, (uint8_t*)key, AES_KEY_SIZE) != 0)
        return PW_CRYPTO;

    return PW_OK;
}
