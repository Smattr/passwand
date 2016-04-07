cmake_minimum_required (VERSION 2.6)
project (passwand)

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -W -Wall -Wextra")

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

find_library (CUNIT NAMES cunit libcunit cunitlib)

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library (passwand src/encoding.c src/erase.c)
target_link_libraries (passwand ${OPENSSL_LIBRARIES})

add_executable (passwand-tests tests/main.c src/encoding.c)
target_link_libraries (passwand-tests passwand ${CUNIT})

enable_testing ()
add_test (UnitTests passwand-tests)
