# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

add_library(module_emu MODULE
  module.c
  detect.c
  emulate.c
  profile.c
  hooks.c
)

target_include_directories(
  module_emu
  PRIVATE
    ..
    ../../include
    ../../
    ${CMAKE_CURRENT_BINARY_DIR}/../..
)

target_include_directories(
  module_emu
  SYSTEM PRIVATE
    ${GLIB2_INCLUDE_DIRS}
    ${LIBEMU_INCLUDE_DIR}
)

add_dependencies(
  module_emu
  dionaea
)

set_target_properties(
  module_emu PROPERTIES
  OUTPUT_NAME emu
  PREFIX ""
)

target_link_libraries(
  module_emu ${LIBEMU_LIBRARIES}
)

########### install files ###############

install(
  TARGETS module_emu
  LIBRARY DESTINATION lib/dionaea
)
