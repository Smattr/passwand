#include <endian.h>
#include "endian.h"
#include <stdint.h>
#include <string.h>

unsigned __int128 htole128(unsigned __int128 host_128bits) {
    unsigned __int128 low = htole64(host_128bits);
    unsigned __int128 high = htole64(host_128bits >> 64);
    return (low << 64) | high;
}

unsigned __int128 le128toh(unsigned __int128 little_endian_128bits) {
    unsigned __int128 low = le64toh(little_endian_128bits);
    unsigned __int128 high = le64toh(little_endian_128bits >> 64);
    return (low << 64) | high;
}
