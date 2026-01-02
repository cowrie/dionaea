# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
# SPDX-FileCopyrightText: 2024 Michel Oosterhof
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Minimal shellcode detector module for Speakeasy integration
# Only includes detection code - analysis is done in Python

add_library(module_speakeasy MODULE
  module.c
  detect.c
)

target_include_directories(
  module_speakeasy
  PRIVATE
    ..
    ../../include
    ../../
    ${CMAKE_CURRENT_BINARY_DIR}/../..
    ${CMAKE_SOURCE_DIR}/vendor/unicorn-libemu-shim/include
)

target_include_directories(
  module_speakeasy
  SYSTEM PRIVATE
    ${GLIB2_INCLUDE_DIRS}
    ${EV_INCLUDE_DIRS}
)

add_dependencies(
  module_speakeasy
  dionaea
  emu_unicorn
)

set_target_properties(
  module_speakeasy PROPERTIES
  OUTPUT_NAME speakeasy
  PREFIX ""
  BUILD_RPATH "/usr/local/lib/python3.13/dist-packages/unicorn/lib"
  INSTALL_RPATH "/usr/local/lib/python3.13/dist-packages/unicorn/lib"
  BUILD_RPATH_USE_ORIGIN ON
  INSTALL_RPATH_USE_LINK_PATH ON
)

target_link_libraries(
  module_speakeasy
  dionaea
  emu_unicorn
  ${GLIB2_LIBRARIES}
)

########### install files ###############

install(
  TARGETS module_speakeasy
  LIBRARY DESTINATION lib/dionaea
)
