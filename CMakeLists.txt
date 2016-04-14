cmake_minimum_required (VERSION 2.6)
project (passwand)

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -W -Wall -Wextra")
add_definitions (-D_XOPEN_SOURCE=700 -D_BSD_SOURCE)

if (NOT CMAKE_BUILD_TYPE)
  set (CMAKE_BUILD_TYPE Release)
endif (NOT CMAKE_BUILD_TYPE)
if (CMAKE_BUILD_TYPE MATCHES Debug)
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb")
else (CMAKE_BUILD_TYPE MATCHES Debug)
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -DNDEBUG")
endif (CMAKE_BUILD_TYPE MATCHES Debug)

find_package (PkgConfig)

pkg_check_modules (OPENSSL REQUIRED openssl)
include_directories (${OPENSSL_INCLUDE_DIRS})

pkg_check_modules (JSON REQUIRED json-c)
include_directories (${JSON_INCLUDE_DIRS})

find_library (CUNIT NAMES cunit libcunit cunitlib)

# Libscrypt seems packaged by distro maintainers (not Colin himself) and it
# gets installed in some messed up way where libscrypt.so is only usable by
# root. To get around this, we have to guide CMake to the install path and
# explicitly direct it to libscrypt.so.0.
find_library (SCRYPT NAME libscrypt.so.0 HINTS /usr/lib)

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library (passwand src/encoding.c src/erase.c src/encryption.c src/export.c
    src/import.c src/random.c)
target_link_libraries (passwand ${OPENSSL_LIBRARIES} ${JSON_LIBRARIES} ${SCRYPT})

add_executable (passwand-tests src/encoding.c src/encryption.c tests/main.c
    tests/test_decode.c tests/test_decrypt.c tests/test_encode.c
    tests/test_encrypt.c tests/test_erase.c tests/test_export.c
    tests/test_import.c tests/test_pack.c tests/test_random_bytes.c
    tests/test_unpack.c tests/util.c)
target_link_libraries (passwand-tests passwand ${CUNIT})

enable_testing ()
add_test (UnitTests passwand-tests)
