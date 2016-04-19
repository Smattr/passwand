/* This file contains types that are only used internally. */

#pragma once

#include <stddef.h>
#include <stdint.h>

/* It is not a typo that the following definitions are identical. The idea is to let the compiler's
 * type checking flag incorrect uses of, e.g., plain text in a function that is expecting cipher
 * text.
 */

/* Master passphrase */
typedef struct {
    uint8_t *data;
    size_t length;
} m_t;

/* Encryption keys */
typedef struct {
    uint8_t *data;
    size_t length;
} k_t;

/* Initialisation vectors */
typedef struct {
    uint8_t *data;
    size_t length;
} iv_t;

/* Encryption salt */
typedef struct {
    uint8_t *data;
    size_t length;
} salt_t;

/* Packed plain text */
typedef struct {
    uint8_t *data;
    size_t length;
} ppt_t;

/* Plain text */
typedef struct {
    uint8_t *data;
    size_t length;
} pt_t;

/* Cipher text */
typedef struct {
    uint8_t *data;
    size_t length;
} ct_t;

/* Message authentication code */
typedef struct {
    uint8_t *data;
    size_t length;
} mac_t;

/* Arbitrary data */
typedef struct {
    uint8_t *data;
    size_t length;
} data_t;
