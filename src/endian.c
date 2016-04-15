#include "endian.h"
#include <stdint.h>
#include <string.h>

unsigned __int128 htole128(unsigned __int128 host_128bits) {
    unsigned __int128 x = 0;
    for (unsigned i = 0; i < sizeof host_128bits; i++) {
        uint8_t byte = host_128bits & 0xff;
        memcpy((void*)&x + i, &byte, sizeof byte);
        host_128bits /= 256;
    }
    return x;
}

unsigned __int128 letoh128(unsigned __int128 little_endian_128bits) {
    unsigned __int128 x = 0;
    for (unsigned i = 0; i < sizeof little_endian_128bits; i++) {
        uint8_t byte;
        memcpy(&byte, (void*)&little_endian_128bits + i, sizeof byte);
        x = (x * 256) + byte;
    }
    return x;
}
