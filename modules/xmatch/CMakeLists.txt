# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

add_library(xmatch MODULE module.c)

target_include_directories(
  xmatch
  PRIVATE
    ..
    ../../include
    ../../
)

target_include_directories(
  xmatch
  SYSTEM PRIVATE
    ${GLIB2_INCLUDE_DIRS}
    ${GMODULE2_INCLUDE_DIRS}
)

link_directories(${GLIB2_LIBRARY_DIRS})
target_link_libraries (xmatch ${GLIB2_LIBRARIES})
target_link_libraries (xmatch ${GMODULE2_LIBRARIES})

########### install files ###############

install(
  TARGETS xmatch
  LIBRARY DESTINATION lib
)
