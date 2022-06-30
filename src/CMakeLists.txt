add_library(passwand
  encoding.c
  erase.c
  encryption.c
  entry.c
  error.c
  export.c
  hmac.c
  import.c
  make_key.c
  malloc.c
  pack.c
  random.c
)

# disable __builtin_memset when we need it not to be optimised out
set_source_files_properties(erase.c PROPERTIES COMPILE_FLAGS -fno-builtin-memset)

target_include_directories(passwand PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
  $<INSTALL_INTERFACE:include>
)

find_library(SCRYPTKDF_LIBRARIES
  NAMES scrypt-kdf libscrypt-kdf
  PATHS ENV LIBRARY_PATH
  REQUIRED)
find_path(SCRYPTKDF_INCLUDE_DIRS scrypt-kdf.h
  PATHS ENV C_INCLUDE_PATH
  REQUIRED)
target_include_directories(passwand SYSTEM PRIVATE ${SCRYPTKDF_INCLUDE_DIRS})
target_link_libraries(passwand PRIVATE ${SCRYPTKDF_LIBRARIES})

find_package(PkgConfig REQUIRED)

pkg_check_modules(OPENSSL REQUIRED openssl)
target_include_directories(passwand SYSTEM PRIVATE ${OPENSSL_INCLUDE_DIRS})
target_link_libraries(passwand PRIVATE ${OPENSSL_LIBRARIES})

pkg_check_modules(JSON REQUIRED json-c)
target_include_directories(passwand SYSTEM PRIVATE ${JSON_INCLUDE_DIRS})
target_link_libraries(passwand PRIVATE ${JSON_LIBRARIES})

install(TARGETS passwand
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY ../include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

export(TARGETS passwand FILE PasswandConfig.cmake)
