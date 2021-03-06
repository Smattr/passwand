cmake_minimum_required(VERSION 3.2 FATAL_ERROR)
project(passwand C)

# this seems to be some magic to get libraries to install correctly
include(GNUInstallDirs)

set(CONFIGURE_TWEAK "")
if(CMAKE_HOST_SYSTEM_NAME STREQUAL "FreeBSD")
  # XXX: CMake documentation claims PkgConfig returns absolute paths to libraries
  # for linking. AFAICT this is false on FreeBSD. Hack around this by teaching it
  # where some of our libraries live.
  link_directories(${LINK_DIRECTORIES} /usr/local/lib)
elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
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

if("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
  add_definitions(-Wtrampolines)
endif()

# enable --as-needed, present on GNU ld on Linux, to minimise dependencies
if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--as-needed")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--as-needed")
endif()

option(USE_WAYLAND "prefer Wayland over X11 for GUI input")

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

# try to find x11
pkg_check_modules(X11 x11)

# try to find Wayland uinput
include(CheckIncludeFile)
check_include_file("linux/uinput.h" HAS_UINPUT)

# Try to find a GUI solution. In order of preference: GTK3, GTK2, osascript
# (MacOS). If none are found, just disable building the GUI client.
pkg_check_modules(GTK3 gtk+-3.0)
if(GTK3_FOUND)
  include_directories(${GTK3_INCLUDE_DIRS})
  set(GTK_LIBRARIES "${GTK3_LIBRARIES}")
else(GTK3_FOUND)
  pkg_check_modules(GTK2 gtk+-2.0)
  if(GTK2_FOUND)
    include_directories(${GTK2_INCLUDE_DIRS})
    set(GTK_LIBRARIES "${GTK2_LIBRARIES}")
  else(GTK2_FOUND)
    find_program(OSASCRIPT osascript)
  endif(GTK2_FOUND)
endif(GTK3_FOUND)

find_package(Threads)

if(GTK3_FOUND OR GTK2_FOUND)
  if(NOT USE_WAYLAND AND X11_FOUND)
    add_executable(pw-gui gui/main.c gui/gtk.c gui/x11.c common/argparse.c)
  elseif(USE_WAYLAND AND HAS_UINPUT)
    add_executable(pw-gui gui/main.c gui/gtk.c gui/wayland.c common/argparse.c)
  endif()
elseif(OSASCRIPT)
  add_executable(pw-gui gui/main.c gui/osascript.c common/argparse.c)
endif()

if(TARGET pw-gui)
  target_link_libraries(pw-gui passwand ${GTK_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
  if(NOT USE_WAYLAND)
    target_link_libraries(pw-gui ${X11_LIBRARIES})
  endif()
  install(TARGETS pw-gui RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
  set(PRIVILEGE_C privilege-macos.c)
else()
  set(PRIVILEGE_C privilege-fallback.c)
endif()

# generate man page content as a C source file
add_custom_command(
  OUTPUT manpage.c
  COMMAND xxd -i passwand.1 >${CMAKE_CURRENT_BINARY_DIR}/manpage.c
  MAIN_DEPENDENCY common/passwand.1
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/common)

add_executable(pw-cli cli/change-main.c cli/check.c cli/delete.c cli/get.c
  cli/generate.c cli/help.c cli/list.c cli/main.c cli/print.c cli/set.c
  cli/update.c common/argparse.c common/${PRIVILEGE_C} manpage.c)
target_link_libraries(pw-cli passwand ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES})
install(TARGETS pw-cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

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

# compress man page
add_custom_target(man-passwand
  ALL
  DEPENDS passwand.1.gz)
add_custom_command(
  OUTPUT passwand.1.gz
  COMMAND gzip -9 --no-name --to-stdout common/passwand.1 >"${CMAKE_CURRENT_BINARY_DIR}/passwand.1.gz"
  MAIN_DEPENDENCY common/passwand.1
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/passwand.1.gz
  DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)

enable_testing()
add_test(UnitTests passwand-tests)
add_test(IntegrationTests ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration-tests.py)
