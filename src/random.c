#include <openssl/rand.h>
#include "random.h"
#include <stddef.h>
#include <stdint.h>

int random_bytes(uint8_t *buffer, size_t buffer_len) {
    return !RAND_bytes(buffer, buffer_len);
}
