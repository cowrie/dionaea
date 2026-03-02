# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

if (Python3_Interpreter_FOUND)
    set(SETUP_PY_IN "${CMAKE_CURRENT_SOURCE_DIR}/setup.py.in2")
    set(SETUP_PY    "${CMAKE_CURRENT_BINARY_DIR}/setup.py")
    set(OUTPUT      "${CMAKE_CURRENT_BINARY_DIR}/build/timestamp")
    set(
        DEPS
        ${CMAKE_CURRENT_SOURCE_DIR}/binding.pyx
    )

    configure_file(${SETUP_PY_IN} ${SETUP_PY})
    # Copy pyproject.toml to build directory for pip install
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/pyproject.toml
        ${CMAKE_CURRENT_BINARY_DIR}/pyproject.toml
        COPYONLY
    )

    add_custom_command(
        OUTPUT ${OUTPUT}
        COMMAND ${Python3_EXECUTABLE} ${SETUP_PY} build
        COMMAND ${CMAKE_COMMAND} -E touch ${OUTPUT}
        DEPENDS ${DEPS}
    )

    add_custom_target(
        python_package
        ALL DEPENDS ${OUTPUT}
    )

    # Use pip install instead of deprecated setup.py install
    install(CODE "execute_process(COMMAND ${Python3_EXECUTABLE} -m pip install --no-build-isolation --no-deps --target=\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${DIONAEA_PYTHON_SITELIBDIR} ${CMAKE_CURRENT_BINARY_DIR})")
endif()

add_library(
    module_python MODULE ""
)

set_target_properties(
    module_python PROPERTIES
    OUTPUT_NAME python
    PREFIX ""
)

target_sources(
    module_python
    PRIVATE
        module.c
)

target_include_directories(
    module_python
    PRIVATE
        ..
        ../../include
        ../../
        ${CMAKE_BINARY_DIR}
)

target_include_directories(
    module_python
    SYSTEM PRIVATE
        ${GLIB2_INCLUDE_DIRS}
        ${GMODULE2_INCLUDE_DIRS}
        ${Python3_INCLUDE_DIRS}
)

target_link_libraries(
    module_python
    ${GLIB2_LIBRARIES}
    ${Python3_LIBRARIES}
    dionaea
)

########### install files ###############

install (
    TARGETS module_python
    LIBRARY DESTINATION ${DIONAEA_MODDIR}
)

include(InstallPythonConfig)

########### install service config ###############
install_available_python_config(
    SOURCE_DIR services
    BUILD_DIR services-available
    DESTINATION_DIR services-available
    FILES
        blackhole.toml
        epmap.toml
        ftp.yaml.in
        http.yaml.in
        memcache.toml
        mirror.toml
        mongo.toml
        mqtt.toml
        mssql.toml
        mysql.toml
        nbns.yaml.in
        pptp.toml
        printer.yaml.in
        sip.yaml.in
        smb.toml
        snmp.toml
        snmptrap.toml
        tftp.yaml.in
        upnp.yaml.in
        wireguard.yaml.in
)

install_enabled_python_config(
    DESTINATION services-enabled
    SOURCE_REL_DIR ../services-available
    FILES
        blackhole.toml
        epmap.toml
        ftp.yaml
        http.yaml
        memcache.toml
        mirror.toml
        mongo.toml
        mqtt.toml
        mssql.toml
        mysql.toml
        nbns.yaml
        pptp.toml
        printer.yaml
        sip.yaml
        smb.toml
        snmp.toml
        snmptrap.toml
        tftp.yaml
        upnp.yaml
        wireguard.yaml
)

########### install ihandler config ###############
install_available_python_config(
    SOURCE_DIR ihandlers
    BUILD_DIR ihandlers-available
    DESTINATION_DIR ihandlers-available
    FILES
        cmdshell.toml
        emuprofile.toml
        emu_scripts.toml
        fail2ban.yaml.in
        ftp.toml
        hpfeeds.toml
        log_db_sql.yaml.in
        log_incident.yaml.in
        log_json.yaml.in
        log_sqlite.yaml.in
        nfq.toml
        p0f.toml
        s3.toml
        speakeasy.toml
        store.toml
        submit_http_post.toml
        submit_http.toml
        tftp_download.toml
        virustotal.yaml.in
)

install_enabled_python_config(
    DESTINATION ihandlers-enabled
    SOURCE_REL_DIR ../ihandlers-available
    FILES
        cmdshell.toml
        emuprofile.toml
        ftp.toml
        log_sqlite.yaml
        speakeasy.toml
        store.toml
        tftp_download.toml
)

##### IHandler

### fail2ban

install(
  DIRECTORY
  DESTINATION ${DIONAEA_STATEDIR}/fail2ban
)

##### Services

### FTP
install(
  DIRECTORY
  DESTINATION ${DIONAEA_STATEDIR}/ftp/root
)

### HTTP
install(
  DIRECTORY
  DESTINATION ${DIONAEA_STATEDIR}/http/root
)

install(
  DIRECTORY
  DESTINATION ${DIONAEA_STATEDIR}/http/template
)

file(
  GLOB_RECURSE item
  RELATIVE "${PROJECT_SOURCE_DIR}/share/python/http/template"
  "${PROJECT_SOURCE_DIR}/share/python/http/template/*.html.j2"
)

message("${item}")
foreach(filename ${item})
  get_filename_component(FILENAME_PATH ${filename} DIRECTORY)
  install_if_not_exists(
    ${PROJECT_SOURCE_DIR}/share/python/http/template/${filename}
    ${DIONAEA_STATEDIR}/http/template/${FILENAME_PATH}
  )
endforeach()

### PRINTER
install(
  DIRECTORY
  DESTINATION ${DIONAEA_STATEDIR}/printer/root
)

install(
  DIRECTORY
  DESTINATION ${DIONAEA_STATEDIR}/printer/root/0
)

### SIP
install(
  DIRECTORY
  DESTINATION ${DIONAEA_STATEDIR}/sip/
)

install(
  DIRECTORY
  DESTINATION ${DIONAEA_STATEDIR}/sip/rtp
)

### TFTP
install(
  DIRECTORY
  DESTINATION ${DIONAEA_STATEDIR}/tftp/root
)

### UPNP
install(
  DIRECTORY
  DESTINATION ${DIONAEA_STATEDIR}/upnp/root
)
