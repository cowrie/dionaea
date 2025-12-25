# ABOUTME: Shared pytest fixtures for dionaea protocol smoke tests
# ABOUTME: Provides dionaea_host and dionaea_ports fixtures configurable via env vars

# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

import os

import pytest


@pytest.fixture(scope="session")
def dionaea_host():
    """Return the host where dionaea is running.

    Override with DIONAEA_HOST environment variable.
    """
    return os.environ.get("DIONAEA_HOST", "127.0.0.1")


@pytest.fixture(scope="session")
def dionaea_ports():
    """Return port mappings for dionaea services.

    Override individual ports with environment variables:
    - DIONAEA_TFTP_PORT
    - DIONAEA_FTP_PORT
    - DIONAEA_SMB_PORT
    - DIONAEA_HTTP_PORT
    - DIONAEA_MYSQL_PORT
    - DIONAEA_EPMAP_PORT
    """
    return {
        "tftp": int(os.environ.get("DIONAEA_TFTP_PORT", 69)),
        "ftp": int(os.environ.get("DIONAEA_FTP_PORT", 21)),
        "smb": int(os.environ.get("DIONAEA_SMB_PORT", 445)),
        "http": int(os.environ.get("DIONAEA_HTTP_PORT", 80)),
        "mysql": int(os.environ.get("DIONAEA_MYSQL_PORT", 3306)),
        "epmap": int(os.environ.get("DIONAEA_EPMAP_PORT", 135)),
        "nbns": int(os.environ.get("DIONAEA_NBNS_PORT", 137)),
    }
