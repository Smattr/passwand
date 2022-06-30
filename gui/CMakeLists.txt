option(ENABLE_GUI "enable building pw-gui" ON)
option(USE_WAYLAND "prefer Wayland over X11 for GUI input")

if(ENABLE_GUI)

  find_package(PkgConfig REQUIRED)

  # try to find a GUI output solution. In order of preference: GTK3, GTK2,
  # osascript (macOS)
  pkg_check_modules(GTK3 gtk+-3.0)
  pkg_check_modules(GTK2 gtk+-2.0)
  find_program(OSASCRIPT osascript)

  if(GTK3_FOUND OR GTK2_FOUND)
    set(OUTPUT_C gtk.c)
  elseif(OSASCRIPT)
    set(OUTPUT_C osascript.c)
  else()
    message(FATAL_ERROR "no viable GUI output mechanism available")
  endif()

  # try to find a GUI input solution
  if(GTK3_FOUND OR GTK2_FOUND)
    if(USE_WAYLAND)
      find_path(WAYLAND_INCLUDE_DIRS linux/uinput.h
        HINTS ENV C_INCLUDE_PATH
        REQUIRED
      )
      set(INPUT_C wayland.c)
    else()
      pkg_check_modules(X11 REQUIRED x11)
      set(INPUT_C x11.c)
    endif()
  elseif(OSASCRIPT)
    # nothing required
    set(INPUT_C)
  else()
    message(FATAL_ERROR "no viable GUI input mechanism available")
  endif()

  add_executable(pw-gui
    main.c
    ../common/argparse.c
    ${OUTPUT_C}
    ${INPUT_C}
  )

  target_link_libraries(pw-gui PRIVATE passwand)

  if(GTK3_FOUND)
    target_include_directories(pw-gui SYSTEM PRIVATE ${GTK3_INCLUDE_DIRS})
    target_link_libraries(pw-gui PRIVATE ${GTK3_LIBRARIES})
  elseif(GTK2_FOUND)
    target_include_directories(pw-gui SYSTEM PRIVATE ${GTK2_INCLUDE_DIRS})
    target_link_libraries(pw-gui PRIVATE ${GTK2_LIBRARIES})
  endif()

  if(GTK3_FOUND OR GTK2_FOUND)
    if(NOT USE_WAYLAND)
      target_include_directories(pw-gui SYSTEM PRIVATE ${X11_INCLUDE_DIRS})
      target_link_libraries(pw-gui PRIVATE ${X11_LIBRARIES})
    endif()
  endif()

  find_package(Threads REQUIRED)
  target_link_libraries(pw-gui PRIVATE ${CMAKE_THREAD_LIBS_INIT})

  add_executable(test-type
    test-type.c
    ${OUTPUT_C}
    ${INPUT_C}
  )

  target_link_libraries(test-type PRIVATE passwand)

  if(GTK3_FOUND)
    target_include_directories(test-type SYSTEM PRIVATE ${GTK3_INCLUDE_DIRS})
    target_link_libraries(test-type PRIVATE ${GTK3_LIBRARIES})
  elseif(GTK2_FOUND)
    target_include_directories(test-type SYSTEM PRIVATE ${GTK2_INCLUDE_DIRS})
    target_link_libraries(test-type PRIVATE ${GTK2_LIBRARIES})
  endif()

  if(GTK3_FOUND OR GTK2_FOUND)
    if(NOT USE_WAYLAND)
      target_include_directories(test-type SYSTEM PRIVATE ${X11_INCLUDE_DIRS})
      target_link_libraries(test-type PRIVATE ${X11_LIBRARIES})
    endif()
  endif()

  install(TARGETS pw-gui
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  )

endif()
