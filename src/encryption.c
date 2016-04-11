/* XXX: libscrypt.h is busted and doesn't include the necessary headers for
 * uint8_t and size_t.
 */
#include <stddef.h>
#include <stdint.h>

#include <libscrypt.h>
#include <stdint.h>
#include <stdlib.h>

static const size_t KEY_SIZE = 32; // bytes

uint8_t *make_key(const uint8_t *master, size_t master_len, const uint8_t *salt,
        size_t salt_len, int work_factor) {

    if (work_factor == -1)
        work_factor = 14; // default value

    if (work_factor < 10 || work_factor > 31)
        return NULL;

    static const uint32_t r = 8;
    static const uint32_t p = 1;

    uint8_t *buffer = malloc(KEY_SIZE);
    if (buffer == NULL)
        return NULL;

    if (libscrypt_scrypt(master, master_len, salt, salt_len,
            ((uint64_t)1) << work_factor, r, p, buffer, KEY_SIZE) != 0) {
        free(buffer);
        return NULL;
    }

    return buffer;
}
