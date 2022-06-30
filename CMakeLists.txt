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

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wformat=2 -Wwrite-strings \
  -Wmissing-prototypes -Wshadow -Wundef")
add_definitions(-D_DEFAULT_SOURCE -D_BSD_SOURCE -D_GNU_SOURCE)

# enable even more warnings if the compiler supports them
include(CheckCCompilerFlag)
CHECK_C_COMPILER_FLAG(-Wcast-align=strict HAS_WARNING_CAST_ALIGN_STRICT)
if(HAS_WARNING_CAST_ALIGN_STRICT)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wcast-align=strict")
endif()
CHECK_C_COMPILER_FLAG(-Wlogical-op HAS_WARNING_LOGICAL_OP)
if(HAS_WARNING_LOGICAL_OP)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wlogical-op")
endif()
CHECK_C_COMPILER_FLAG(-Wpointer-arith HAS_WARNING_POINTER_ARITH)
if(HAS_WARNING_POINTER_ARITH)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wpointer-arith")
endif()
CHECK_C_COMPILER_FLAG(-Wstrict-aliasing=1 HAS_WARNING_STRICT_ALIASING_1)
if(HAS_WARNING_STRICT_ALIASING_1)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wstrict-aliasing=1")
endif()
CHECK_C_COMPILER_FLAG(-Wtrampolines HAS_WARNING_TRAMPOLINES)
if(HAS_WARNING_TRAMPOLINES)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wtrampolines")
endif()

# enable --as-needed, present on GNU ld on Linux, to minimise dependencies
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--as-needed")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--as-needed")
endif()

add_subdirectory(cli)
add_subdirectory(gui)
add_subdirectory(src)
add_subdirectory(tests)

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
