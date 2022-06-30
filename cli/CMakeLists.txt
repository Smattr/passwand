if(APPLE)
  set(PRIVILEGE_C privilege-macos.c)
else()
  set(PRIVILEGE_C privilege-fallback.c)
endif()

add_executable(pw-cli
  change-main.c
  check.c
  delete.c
  get.c
  generate.c
  help.c
  list.c
  main.c
  print.c
  set.c
  update.c
  ../common/argparse.c
  ../common/${PRIVILEGE_C}
  ${CMAKE_CURRENT_BINARY_DIR}/manpage.c
)

target_link_libraries(pw-cli PRIVATE passwand)

find_package(PkgConfig REQUIRED)

pkg_check_modules(OPENSSL REQUIRED openssl)
target_include_directories(pw-cli SYSTEM PRIVATE ${OPENSSL_INCLUDE_DIRS})
target_link_libraries(pw-cli PRIVATE ${OPENSSL_LIBRARIES})

find_package(Threads REQUIRED)
target_link_libraries(pw-cli PRIVATE ${CMAKE_THREAD_LIBS_INIT})

# generate man page content as a C source file
find_program(XXD xxd REQUIRED)
add_custom_command(
  OUTPUT manpage.c
  COMMAND ${XXD} -include passwand.1 >${CMAKE_CURRENT_BINARY_DIR}/manpage.c
  MAIN_DEPENDENCY ../common/passwand.1
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../common
)

# compress man page
find_program(GZIP gzip REQUIRED)
add_custom_target(man-passwand
  ALL
  DEPENDS passwand.1.gz
)
add_custom_command(
  OUTPUT passwand.1.gz
  COMMAND ${GZIP} -9 --no-name --to-stdout ../common/passwand.1
    >"${CMAKE_CURRENT_BINARY_DIR}/passwand.1.gz"
  MAIN_DEPENDENCY ../common/passwand.1
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

install(TARGETS pw-cli
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/passwand.1.gz
  DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
)
