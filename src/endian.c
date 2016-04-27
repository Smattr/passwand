#include <endian.h>
#include "endian.h"
#include <stdint.h>
#include <string.h>

typedef unsigned __int128 uint128_t;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

uint128_t htole128(uint128_t host_128bits) {
    return host_128bits;
}

uint128_t le128toh(uint128_t little_endian_128bits) {
    return little_endian_128bits;
}

uint128_t htobe128(uint128_t host_128bits) {
    return (((uint128_t)htobe64(host_128bits)) << 64) |
            ((uint128_t)htobe64(host_128bits >> 64));
}

uint128_t be128toh(uint128_t big_endian_128bits) {
    return (((uint128_t)be64toh(big_endian_128bits)) << 64) |
            ((uint128_t)be64toh(big_endian_128bits >> 64));
}

#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

uint128_t htole128(uint128_t host_128bits) {
    return (((uint128_t)htole64(host_128bits)) << 64) |
            ((uint128_t)htole64(host_128bits >> 64));
}

uint128_t le128toh(uint128_t little_endian_128bits) {
    return (((uint128_t)le64toh(little_endian_128bits)) << 64) |
            ((uint128_t)le64toh(little_endian_128bits >> 64));
}

uint128_t htobe128(uint128_t host_128bits) {
    return host_128bits;
}

uint128_t be128toh(uint128_t big_endian_128bits) {
    return big_endian_128bits;
}

#endif
