# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

add_library(module_nfq MODULE nfq.c)

target_include_directories(
  module_nfq
  PRIVATE
    ..
    ../../include
    ../../src
    ../../
    ${CMAKE_CURRENT_BINARY_DIR}/../..
)

target_include_directories(
  module_nfq
  SYSTEM PRIVATE
    ${GMODULE2_INCLUDE_DIRS}
    ${NFQUEUE_INCLUDE_DIRS}
)

add_dependencies(
  module_nfq
  dionaea
)

set_target_properties(
  module_nfq PROPERTIES
  OUTPUT_NAME nfq
  PREFIX ""
)

target_link_libraries(
  module_nfq
  dionaea
  ${GMODULE2_LIBRARIES}
  ${NFQUEUE_LIBRARIES}
)

########### install files ###############

install(
  TARGETS module_nfq
  LIBRARY DESTINATION lib/dionaea
)
