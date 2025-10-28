# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

FROM ubuntu:24.04 AS builder

ARG DEBIAN_FRONTEND=noninteractive

ENV DIONAEA_GROUP=dionaea \
    DIONAEA_USER=dionaea \
    DIONAEA_HOME=/opt/dionaea

# Set locale to UTF-8, otherwise upstream libraries have bytes/string conversion issues
ENV LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    LANGUAGE=C.UTF-8

RUN groupadd -r ${DIONAEA_GROUP} && \
    useradd -r -d ${DIONAEA_HOME} -m -g ${DIONAEA_GROUP} ${DIONAEA_USER}
#    adduser --system --no-create-home --shell /bin/bash --disabled-password --disabled-login

COPY . /code

# no libemu-dev/libemu2 for now, explore https://github.com/mandiant/unicorn-libemu-shim/tree/master
RUN apt-get update && \
    apt-get -qq install -y \
        -o APT::Install-Suggests=false \
        -o APT::Install-Recommends=false \
        -o Dpkg::Use-Pty="0" \
        build-essential \
        cmake \
        cython3 \
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
        python3-setuptools \
        python3-bson \
        python3-yaml \
        python3-boto3 \
        fonts-liberation

RUN   mkdir -p /code/build && \
      cd /code/build && \
      cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea /code && \
      make && \
      make install && \
      chown -R dionaea:dionaea /opt/dionaea/var && \
      cp /code/docker/entrypoint.sh /opt/dionaea/entrypoint.sh && \
      mkdir -p /opt/dionaea/template && \
      (cd /opt/dionaea && mv var/lib template/ && mv var/log template/ && mv etc template/)


FROM ubuntu:24.04 AS runtime

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
        ca-certificates \
        libcurl4 \
        libev4 \
        libglib2.0-0 \
        libnetfilter-queue1 \
        libpcap0.8 \
        libpython3.12t64 \
        libudns0 && \
    apt-get autoremove --purge -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=builder --chown=${DIONAEA_USER}:${DIONAEA_GROUP} ${DIONAEA_HOME} ${DIONAEA_HOME}

ENTRYPOINT ["/opt/dioanea/entrypoint.sh"]
