#include <passwand/passwand.h>

const char *passwand_error(passwand_error_t err) {
  switch (err) {
  case PW_OK:
    return "no error";
  case PW_IO:
    return "I/O error";
  case PW_NO_MEM:
    return "out of memory";
  case PW_OVERFLOW:
    return "integer overflow";
  case PW_BAD_KEY_SIZE:
    return "incorrect key length";
  case PW_BAD_IV_SIZE:
    return "incorrect initialisation vector length";
  case PW_BAD_WF:
    return "incorrect work factor";
  case PW_UNALIGNED:
    return "unaligned data";
  case PW_CRYPTO:
    return "failure in underlying crypto library";
  case PW_HEADER_MISMATCH:
    return "mismatched header value";
  case PW_IV_MISMATCH:
    return "mismatched initialisation vector";
  case PW_TRUNCATED:
    return "data was too short";
  case PW_BAD_PADDING:
    return "data was incorrectly padded";
  case PW_BAD_JSON:
    return "imported data did not conform to expected schema";
  case PW_BAD_HMAC:
    return "message failed authentication";
  }
  return NULL;
}
