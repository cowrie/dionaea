# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

add_library(module_pcap MODULE pcap.c)

target_include_directories(
  module_pcap
  PRIVATE
    ..
    ../../include
    ../../
    ${CMAKE_CURRENT_BINARY_DIR}/../..
)

target_include_directories(
  module_pcap
  SYSTEM PRIVATE
    ${GMODULE2_INCLUDE_DIRS}
)

set_target_properties(
  module_pcap PROPERTIES
  OUTPUT_NAME pcap
  PREFIX ""
)

target_link_libraries(
  module_pcap
  dionaea
  ${GMODULE2_LIBRARIES}
  PCAP::PCAP
)

########### install files ###############

install(
  TARGETS module_pcap
  LIBRARY DESTINATION lib/dionaea
)
