// This file contains types that are only used internally.

#pragma once

#include <passwand/passwand.h>
#include <stddef.h>
#include <stdint.h>

// It is not a typo that the following definitions are identical. The idea is to
// let the compiler's type checking flag incorrect uses of, e.g., plain text in
// a function that is expecting cipher text.

// Main passphrase
typedef struct {
  uint8_t *data;
  size_t length;
} m_t;

// Encryption keys
typedef uint8_t k_t[AES_KEY_SIZE];

// Initialisation vectors
typedef uint8_t iv_t[PW_IV_LEN];

// Encryption salt
typedef struct {
  uint8_t *data;
  size_t length;
} salt_t;

// Packed plain text
typedef struct {
  uint8_t *data;
  size_t length;
} ppt_t;

// Plain text
typedef struct {
  uint8_t *data;
  size_t length;
} pt_t;

// Cipher text
typedef struct {
  uint8_t *data;
  size_t length;
} ct_t;

// Message authentication code
typedef struct {
  uint8_t *data;
  size_t length;
} mac_t;

// Arbitrary data
typedef struct {
  uint8_t *data;
  size_t length;
} data_t;
