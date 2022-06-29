add_executable(passwand-tests

  # internal library files whose contents we need to expose
  ../src/encoding.c
  ../src/encryption.c
  ../src/pack.c
  ../src/random.c
    
  # actual test sources
  main.c
  test_decode.c
  test_decrypt.c
  test_encode.c
  test_encrypt.c
  test_entry_new.c
  test_entry_check_mac.c
  test_entry_set_mac.c
  test_erase.c
  test_export.c
  test_import.c
  test_integration.c
  test_malloc.c
  test_pack.c
  test_random_bytes.c
  test_unpack.c
  util.c
)

# FIXME
target_include_directories(passwand-tests PRIVATE ../include)

target_link_libraries(passwand-tests PRIVATE passwand)

find_path(CUNIT_INCLUDE_DIRS CUnit/CUnit.h HINTS ENV C_INCLUDE_PATH REQUIRED)
find_library(CUNIT_LIBRARIES
  NAMES cunit libcunit cunitlib
  HINTS ENV LIBRARY_PATH
  REQUIRED
)
target_include_directories(passwand-tests SYSTEM PRIVATE ${CUNIT_INCLUDE_DIRS})
target_link_libraries(passwand-tests PRIVATE ${CUNIT_LIBRARIES})

add_executable(pw-gui-test-stub
  gui-test-stub.c
  ../gui/main.c
  ../common/argparse.c
)

# FIXME
target_include_directories(pw-gui-test-stub PRIVATE ../include)

target_link_libraries(pw-gui-test-stub PRIVATE passwand)

find_package(Threads REQUIRED)
target_link_libraries(pw-gui-test-stub PRIVATE ${CMAKE_THREAD_LIBS_INIT})

find_package(Python3 COMPONENTS Interpreter REQUIRED)

add_custom_target(check
  COMMAND passwand-tests
  COMMAND env
    PATH=${CMAKE_BINARY_DIR}/cli:${CMAKE_CURRENT_BINARY_DIR}:$ENV{PATH}
    ${CMAKE_CURRENT_SOURCE_DIR}/integration-tests.py --verbose
)
