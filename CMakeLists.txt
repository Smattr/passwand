cmake_minimum_required(VERSION 3.18 FATAL_ERROR)
project(passwand C)

# this seems to be some magic to get libraries to install correctly
include(GNUInstallDirs)

set(CONFIGURE_TWEAK "")
if(CMAKE_HOST_SYSTEM_NAME STREQUAL "FreeBSD")
  # XXX: CMake documentation claims PkgConfig returns absolute paths to libraries
  # for linking. AFAICT this is false on FreeBSD. Hack around this by teaching it
  # where some of our libraries live.
  link_directories(${LINK_DIRECTORIES} /usr/local/lib)
elseif(APPLE)
  # add paths for Macports or Homebrew
  if(EXISTS /opt/local/include)
    if(EXISTS /usr/local/opt/openssl/include)
      set(CONFIGURE_TWEAK env "CFLAGS=-I /opt/local/include -I /usr/local/opt/openssl/include")
    else()
      set(CONFIGURE_TWEAK env "CFLAGS=-I /opt/local/include")
    endif()
  else()
    if(EXISTS /usr/local/opt/openssl/include)
      set(CONFIGURE_TWEAK env "CFLAGS=-I /usr/local/opt/openssl/include")
    else()
      set(CONFIGURE_TWEAK "")
    endif()
  endif()
  if(EXISTS /opt/local/lib)
    link_directories(${LINK_DIRECTORIES} /opt/local/lib)
  endif()
  if(EXISTS /usr/local/opt/openssl/lib)
    link_directories(${LINK_DIRECTORIES} /usr/local/opt/openssl/lib)
  endif()
endif()

add_compile_options(-std=c11 -W -Wall -Wextra -Wformat=2 -Wwrite-strings
  -Wmissing-prototypes -Wshadow -Wundef)
add_definitions(-D_DEFAULT_SOURCE -D_BSD_SOURCE -D_GNU_SOURCE)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  add_definitions(-Wtrampolines)
endif()

# enable --as-needed, present on GNU ld on Linux, to minimise dependencies
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--as-needed")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--as-needed")
endif()

# disable __builtin_memset when we need it not to be optimised out
set_source_files_properties(src/erase.c PROPERTIES COMPILE_FLAGS -fno-builtin-memset)

find_package(PkgConfig)

pkg_check_modules(OPENSSL REQUIRED openssl)
include_directories(${OPENSSL_INCLUDE_DIRS})

pkg_check_modules(JSON REQUIRED json-c)
include_directories(${JSON_INCLUDE_DIRS})

find_library(CUNIT NAMES cunit libcunit cunitlib)

find_library(SCRYPTKDF_LIBRARIES NAMES scrypt-kdf libscrypt-kdf
  PATHS ENV LIBRARY_PATH)
find_path(SCRYPTKDF_INCLUDE_DIRS scrypt-kdf.h
  PATHS ENV C_INCLUDE_PATH)

find_package(Threads)

add_subdirectory(cli)
add_subdirectory(gui)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(passwand src/encoding.c src/erase.c src/encryption.c src/entry.c src/error.c
    src/export.c src/hmac.c src/import.c src/make_key.c src/malloc.c src/pack.c src/random.c)
target_include_directories(passwand PRIVATE ${SCRYPTKDF_INCLUDE_DIRS})
target_link_libraries(passwand ${OPENSSL_LIBRARIES} ${JSON_LIBRARIES} ${SCRYPTKDF_LIBRARIES})
install(TARGETS passwand
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

add_executable(passwand-tests

    # internal library files whose contents we need to expose
    src/encoding.c src/encryption.c src/pack.c src/random.c
    
    # actual test sources
    tests/main.c tests/test_decode.c tests/test_decrypt.c tests/test_encode.c tests/test_encrypt.c
    tests/test_entry_new.c tests/test_entry_check_mac.c tests/test_entry_set_mac.c
    tests/test_erase.c tests/test_export.c tests/test_import.c tests/test_integration.c
    tests/test_malloc.c tests/test_pack.c tests/test_random_bytes.c tests/test_unpack.c
    tests/util.c)
target_link_libraries(passwand-tests passwand ${CUNIT})

add_executable(pw-gui-test-stub gui/main.c common/argparse.c tests/gui-test-stub.c)
target_link_libraries(pw-gui-test-stub passwand ${CMAKE_THREAD_LIBS_INIT})

add_custom_target(check
  COMMAND passwand-tests
  COMMAND env PATH=${CMAKE_BINARY_DIR}/cli:$ENV{PATH}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration-tests.py --verbose
)

find_program(CLANG_FORMAT
  NAMES
    clang-format
    clang-format-mp-14 clang-format-14
    clang-format-mp-13 clang-format-13
    clang-format-mp-12 clang-format-12
    clang-format-mp-11 clang-format-11)
find_program(GIT git)
find_program(XARGS xargs)
if(CLANG_FORMAT AND GIT AND XARGS)
  add_custom_target(format
    COMMAND ${GIT} ls-files -z '**/*.c' '**/*.h' |
      ${XARGS} -0 -- ${CLANG_FORMAT} -i --style=file
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "clang-formatting sources")
endif()
