#include <assert.h>
#include "internal.h"
#include <passwand/passwand.h>
#include <scrypt-kdf.h>
#include <stddef.h>
#include <stdint.h>
#include "types.h"

passwand_error_t make_key(const m_t *mainkey, const salt_t *salt, int work_factor, k_t key) {

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
            ((uint64_t)1) << work_factor, r, p, (uint8_t*)key, AES_KEY_SIZE) != 0)
        return PW_CRYPTO;

    return PW_OK;
}
