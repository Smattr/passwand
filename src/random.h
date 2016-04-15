#pragma once

#include <passwand/passwand.h>
#include <stddef.h>
#include <stdint.h>

/** Generate some random bytes
 *
 * @param[out] buffer Random data
 * @param buffer_len  Number of bytes requested
 * @return            PW_OK on success
 */
passwand_error_t random_bytes(uint8_t *buffer, size_t buffer_len)
    __attribute__((visibility("internal")));
