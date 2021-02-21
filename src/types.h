// this file contains types that are only used internally

#pragma once

#include <passwand/passwand.h>
#include <stddef.h>
#include <stdint.h>

// It is not a typo that the following definitions are identical. The idea is to
// let the compiler’s type checking flag incorrect uses of, e.g., plain text in
// a function that is expecting cipher text.

// main passphrase
typedef struct {
  uint8_t *data;
  size_t length;
} m_t;

// encryption keys
typedef uint8_t k_t[AES_KEY_SIZE];

// initialisation vectors
typedef uint8_t iv_t[PW_IV_LEN];

// encryption salt
typedef struct {
  uint8_t *data;
  size_t length;
} salt_t;

// packed plain text
typedef struct {
  uint8_t *data;
  size_t length;
} ppt_t;

// plain text
typedef struct {
  uint8_t *data;
  size_t length;
} pt_t;

// cipher text
typedef struct {
  uint8_t *data;
  size_t length;
} ct_t;

// message authentication code
typedef struct {
  uint8_t *data;
  size_t length;
} mac_t;

// arbitrary data
typedef struct {
  uint8_t *data;
  size_t length;
} data_t;
