#pragma once

#include <stdint.h>

unsigned __int128 htole128(unsigned __int128 host_128bits);

unsigned __int128 le128toh(unsigned __int128 little_endian_128bits);

unsigned __int128 htobe128(unsigned __int128 host_128bits);

unsigned __int128 be128toh(unsigned __int128 big_endian_128bits);
