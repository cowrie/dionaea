#!/bin/sh
# ABOUTME: Container entrypoint for the dionaea honeypot.
# ABOUTME: Enables core dumps if allowed, then execs the daemon.

# Enable core dumps (requires: docker run --ulimit core=-1)
ulimit -c unlimited 2>/dev/null || true

if [ -w /proc/sys/kernel/core_pattern ]; then
    echo "/opt/dionaea/var/dionaea/core.%e.%p.%t" > /proc/sys/kernel/core_pattern
fi

exec /opt/dionaea/bin/dionaea -c /opt/dionaea/conf/dionaea.toml "$@"
