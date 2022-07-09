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

target_link_libraries(passwand-tests PRIVATE passwand)

find_package(PkgConfig REQUIRED)

pkg_check_modules(OPENSSL REQUIRED openssl)
target_include_directories(passwand-tests SYSTEM PRIVATE ${OPENSSL_INCLUDE_DIRS})
target_link_libraries(passwand-tests PRIVATE ${OPENSSL_LIBRARIES})

add_executable(pw-gui-test-stub
  gui-test-stub.c
  ../gui/main.c
  ../common/argparse.c
)

target_link_libraries(pw-gui-test-stub PRIVATE passwand)

find_package(Threads REQUIRED)
target_link_libraries(pw-gui-test-stub PRIVATE ${CMAKE_THREAD_LIBS_INIT})

find_package(Python3 COMPONENTS Interpreter REQUIRED)

execute_process(
  COMMAND ${Python3_EXECUTABLE} -c "import pytest"
  RESULT_VARIABLE IMPORT_PYTEST_RET
  OUTPUT_QUIET
  ERROR_QUIET
)
if(NOT ${IMPORT_PYTEST_RET} EQUAL 0)
  message(FATAL_ERROR "pytest not found")
endif()

add_custom_target(check
  COMMAND passwand-tests
  COMMAND env
    PATH=${CMAKE_BINARY_DIR}/cli:${CMAKE_CURRENT_BINARY_DIR}:$ENV{PATH}
    ${Python3_EXECUTABLE} -m pytest
    ${CMAKE_CURRENT_SOURCE_DIR}/integration-tests.py --verbose
)
