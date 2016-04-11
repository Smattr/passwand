/* XXX: libscrypt.h is busted and doesn't include the necessary headers for
 * uint8_t and size_t.
 */
#include <stddef.h>
#include <stdint.h>

#include <fcntl.h>
#include <libscrypt.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const size_t KEY_SIZE = 32; // bytes

static const char HEADER[] = "oprime01";

int random_bytes(uint8_t *buffer, size_t buffer_len) {
    /* XXX: This should really use getrandom when it's more widely available. */

    /* This is the limit at which getrandom can fail. For this library we
     * shouldn't ever need to read more than 16 bytes.
     */
    if (buffer_len > 256)
        return -1;

    int fd = open("/dev/random", O_RDONLY);
    if (fd == -1)
        return -1;

    ssize_t r = read(fd, buffer, buffer_len);
    close(fd);
    if (r != (ssize_t)buffer_len)
        return -1;

    return 0;
}

int make_key(const uint8_t *master, size_t master_len, const uint8_t *salt,
        size_t salt_len, int work_factor, uint8_t *buffer) {

    if (work_factor == -1)
        work_factor = 14; // default value

    if (work_factor < 10 || work_factor > 31)
        return -1;

    static const uint32_t r = 8;
    static const uint32_t p = 1;

    if (libscrypt_scrypt(master, master_len, salt, salt_len,
            ((uint64_t)1) << work_factor, r, p, buffer, KEY_SIZE) != 0)
        return -1;

    return 0;
}

int mac(const uint8_t *master, size_t master_len, const uint8_t *data,
        size_t data_len, uint8_t **salt, uint8_t *auth, size_t *auth_len,
        int work_factor) {

    static const size_t SALT_LEN = 8;
    bool salt_malloced = false;

    if (*salt == NULL) {

        *salt = malloc(SALT_LEN);
        if (*salt == NULL)
            return -1;

        if (random_bytes(*salt, SALT_LEN) != 0) {
            free(*salt);
            return -1;
        }

        salt_malloced = true;
    }

    uint8_t key[KEY_SIZE];
    if (make_key(master, master_len, *salt, SALT_LEN, work_factor, key) != 0) {
        if (salt_malloced)
            free(*salt);
        return -1;
    }

    const EVP_MD *sha512 = EVP_sha512();

    //unsigned char md[EVP_MAX_MD_SIZE];
    unsigned md_len;
    if (HMAC(sha512, key, KEY_SIZE, data, data_len, auth, &md_len) == NULL) {
        if (salt_malloced)
            free(*salt);
        return -1;
    }

    *auth_len = (size_t)md_len;

    return 0;
}
