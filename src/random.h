#pragma once

#include <stddef.h>
#include <stdint.h>

/** Generate some random bytes
 *
 * @param[out] buffer Random data
 * @param buffer_len  Number of bytes requested
 * @return            0 on success
 */
int random_bytes(uint8_t *buffer, size_t buffer_len)
    __attribute__((visibility("internal")));
