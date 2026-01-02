# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

FROM debian:trixie-slim AS builder

ARG DEBIAN_FRONTEND=noninteractive

ENV DIONAEA_GROUP=dionaea \
    DIONAEA_USER=dionaea \
    DIONAEA_HOME=/opt/dionaea

# Set locale to UTF-8, otherwise upstream libraries have bytes/string conversion issues
ENV LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    LANGUAGE=C.UTF-8

RUN groupadd -r ${DIONAEA_GROUP} && \
    useradd -r -d ${DIONAEA_HOME} -g ${DIONAEA_GROUP} ${DIONAEA_USER}
#    adduser --system --no-create-home --shell /bin/bash --disabled-password --disabled-login

COPY . /code

# no libemu-dev/libemu2 for now, explore https://github.com/mandiant/unicorn-libemu-shim/tree/master
RUN apt-get update && \
    apt-get -qq install -y \
        -o APT::Install-Suggests=false \
        -o APT::Install-Recommends=false \
        -o Dpkg::Use-Pty="0" \
        -o Dpkg::Progress-Fancy="0" \
        build-essential \
        cmake \
        curl \
        cython3 \
        git \
        libcurl4-openssl-dev \
        libev-dev \
        libglib2.0-dev \
        libnetfilter-queue-dev \
        libpcap-dev \
        libssl-dev \
        libtool \
        libudns-dev \
        python3 \
        python3-dev \
        python3-pip \
        python3-construct \
        python3-setuptools \
        python3-bson \
        python3-yaml \
        fonts-liberation && \
    pip install --break-system-packages speakeasy-emulator

RUN   git config --global --add safe.directory /code && \
      cd /code && git checkout . && \
      mkdir -p /code/build && \
      cd /code/build && \
      cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea /code && \
      make && \
      make install && \
      chown -R dionaea:dionaea /opt/dionaea/var && \
      cp /code/docker/entrypoint.sh /opt/dionaea/entrypoint.sh && \
      mkdir -p /opt/dionaea/template && \
      (cd /opt/dionaea && mv var/lib template/ && mv var/log template/ && mv etc template/)


FROM debian:trixie-slim AS runtime

ARG DEBIAN_FRONTEND=noninteractive

ENV DIONAEA_GROUP=dionaea \
    DIONAEA_USER=dionaea \
    DIONAEA_HOME=/opt/dionaea

ENV LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    LANGUAGE=C.UTF-8

RUN groupadd -r ${DIONAEA_GROUP} && \
    useradd -r -d ${DIONAEA_HOME} -m -g ${DIONAEA_GROUP} ${DIONAEA_USER}

RUN apt-get update && \
    apt-get -qq install -y \
        -o APT::Install-Suggests=false \
        -o APT::Install-Recommends=false \
        -o Dpkg::Use-Pty="0" \
        gdb \
        vim-tiny \
        netcat-openbsd \
        curl \
        ca-certificates \
        libcap2-bin \
        libcurl4 \
        libev4 \
        libglib2.0-0 \
        libnetfilter-queue1 \
        libpcap0.8 \
        libudns0 \
        python3 \
        python3-construct \
        python3-setuptools \
        python3-bson \
        python3-yaml \
        fonts-liberation && \
    apt-get autoremove --purge -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=builder --chown=${DIONAEA_USER}:${DIONAEA_GROUP} ${DIONAEA_HOME} ${DIONAEA_HOME}

# Copy Python packages (unicorn, speakeasy, and dependencies) from builder stage
COPY --from=builder /usr/local/lib/python3.13/dist-packages /usr/local/lib/python3.13/dist-packages

# Create symlink for unicorn library (pip installs as libunicorn.so but we need libunicorn.so.1)
RUN ln -s /usr/local/lib/python3.13/dist-packages/unicorn/lib/libunicorn.so \
          /usr/local/lib/python3.13/dist-packages/unicorn/lib/libunicorn.so.1

RUN setcap cap_net_bind_service=+ep /opt/dionaea/bin/dionaea

ENTRYPOINT ["/opt/dionaea/entrypoint.sh"]
