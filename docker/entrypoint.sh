#!/bin/sh
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2020 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

init_etc () {
    (cd /opt/dionaea/ && cp -au template/etc .)
}

init_lib () {
    (cd /opt/dionaea/ && cp -au template/lib var/)
}

init_log () {
    (cd /opt/dionaea/ && cp -au template/log var/)
}

if [ "x$DIONAEA_FORCE_INIT" = "x1" ]; then
    echo "Forced to copy files ..."
    init_etc
    init_lib
    init_log
elif [ "x$DIONAEA_SKIP_INIT" = "x" ]; then
    test ! -d /opt/dionaea/etc/dionaea && init_etc
    test ! -d /opt/dionaea/var/lib/dionaea && init_lib
    test ! -d /opt/dionaea/var/log/dionaea && init_log
fi

if [ "x$DIONAEA_FORCE_INIT_CONF" = "x1" ]; then
    init_etc
fi

if [ "x$DIONAEA_FORCE_INIT_DATA" = "x1" ]; then
    init_lib
    init_log
fi

# Enable core dumps
# Requires: docker run --ulimit core=-1
ulimit -c unlimited 2>/dev/null || true

# Set core pattern (requires --privileged or set on host)
if [ -w /proc/sys/kernel/core_pattern ]; then
    echo "/opt/dionaea/var/lib/dionaea/core.%e.%p.%t" > /proc/sys/kernel/core_pattern
fi

echo "Starting dionaea ..."
exec /opt/dionaea/bin/dionaea -u dionaea -g dionaea -c /opt/dionaea/etc/dionaea/dionaea.cfg "$@"
