# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

add_library(module_curl MODULE module.c)

target_include_directories(
  module_curl
  PRIVATE
    ..
    ../../include
    ../../src
    ../../
    ${CMAKE_CURRENT_BINARY_DIR}/../..
)

target_include_directories(
  module_curl
  SYSTEM PRIVATE
    ${GMODULE2_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
)

add_dependencies(
  module_curl
  dionaea
)

set_target_properties(
  module_curl PROPERTIES
  OUTPUT_NAME curl
  PREFIX ""
)

target_link_libraries(
  module_curl
  dionaea
  ${CURL_LIBRARIES}
  ${GMODULE2_LIBRARIES}
)

########### install files ###############

install(
  TARGETS module_curl
  LIBRARY DESTINATION lib/dionaea
)
