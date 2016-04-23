cmake_minimum_required (VERSION 2.6)
project (passwand)

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -W -Wall -Wextra -Wtrampolines")
add_definitions (-D_XOPEN_SOURCE=700 -D_BSD_SOURCE -D_GNU_SOURCE)

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

# Libscrypt seems packaged by distro maintainers (not Colin himself) and it gets installed in some
# messed up way where libscrypt.so is only usable by root. To get around this, we have to guide
# CMake to the install path and explicitly direct it to libscrypt.so.0.
find_library (SCRYPT NAME libscrypt.so.0 HINTS /usr/lib)

# Try to find GTK3 or, failing that, GTK2. If neither are found, just disable building the GUI
# client.
pkg_check_modules (GTK3 gtk+-3.0)
if (GTK3_FOUND)
  include_directories (${GTK3_INCLUDE_DIRS})
  set (GTK_LIBRARIES "${GTK3_LIBRARIES}")
else (GTK3_FOUND)
  pkg_check_modules (GTK2 gtk+-2.0)
  if (GTK2_FOUND)
    include_directories (${GTK2_INCLUDE_DIRS})
    set (GTK_LIBRARIES "${GTK2_LIBRARIES}")
  endif (GTK2_FOUND)
endif (GTK3_FOUND)

if (GTK3_FOUND OR GTK2_FOUND)
  add_executable (pw-gui exe/gui.c)
  target_link_libraries (pw-gui ${GTK_LIBRARIES})
endif (GTK3_FOUND OR GTK2_FOUND)

add_executable (pw-cli exe/cli.c exe/argparse.c)
target_link_libraries (pw-cli passwand)

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library (passwand src/encoding.c src/erase.c src/encryption.c src/endian.c src/entry.c
    src/error.c src/export.c src/hmac.c src/import.c src/make_key.c src/malloc.c src/pack.c
    src/random.c)
target_link_libraries (passwand ${OPENSSL_LIBRARIES} ${JSON_LIBRARIES} ${SCRYPT})

add_executable (passwand-tests

    # Internal library files whose contents we need to expose.
    src/encoding.c src/encryption.c src/pack.c src/random.c
    
    # Actual test sources.
    tests/main.c tests/test_decode.c tests/test_decrypt.c tests/test_encode.c tests/test_encrypt.c
    tests/test_entry_new.c tests/test_entry_check_mac.c tests/test_entry_set_mac.c
    tests/test_erase.c tests/test_export.c tests/test_import.c tests/test_integration.c
    tests/test_malloc.c tests/test_pack.c tests/test_random_bytes.c tests/test_unpack.c
    tests/util.c)
target_link_libraries (passwand-tests passwand ${CUNIT})

enable_testing ()
add_test (UnitTests passwand-tests)
