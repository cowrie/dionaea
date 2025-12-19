# ABOUTME: FTP protocol smoke tests for dionaea honeypot
# ABOUTME: Tests banner, login, and basic commands using stdlib ftplib

# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

import ftplib
import socket


def test_ftp_connect_banner(dionaea_host, dionaea_ports):
    """Test that FTP server sends a 220 banner on connect."""
    port = dionaea_ports["ftp"]

    ftp = ftplib.FTP()
    ftp.connect(dionaea_host, port, timeout=10)
    try:
        # getwelcome() returns the 220 banner
        welcome = ftp.getwelcome()
        assert welcome.startswith("220"), f"Expected 220 banner, got: {welcome}"
    finally:
        try:
            ftp.quit()
        except Exception:
            pass


def test_ftp_anonymous_login(dionaea_host, dionaea_ports):
    """Test anonymous login to FTP server."""
    port = dionaea_ports["ftp"]

    ftp = ftplib.FTP()
    ftp.connect(dionaea_host, port, timeout=10)
    try:
        # Anonymous login - dionaea should accept it
        response = ftp.login("anonymous", "test@test.com")
        # 230 = Login successful, 530 = Login failed
        # Both are valid responses for a honeypot
        assert response.startswith("2") or response.startswith("5")
    finally:
        try:
            ftp.quit()
        except Exception:
            pass


def test_ftp_user_login(dionaea_host, dionaea_ports):
    """Test user authentication to FTP server."""
    port = dionaea_ports["ftp"]

    ftp = ftplib.FTP()
    ftp.connect(dionaea_host, port, timeout=10)
    try:
        # Try to login with fake credentials
        # Honeypot may accept or reject - we just want a response
        ftp.login("testuser", "testpass")
    except ftplib.error_perm:
        # Permission denied is a valid response
        pass
    finally:
        try:
            ftp.quit()
        except Exception:
            pass


def test_ftp_pwd_command(dionaea_host, dionaea_ports):
    """Test PWD command after login."""
    port = dionaea_ports["ftp"]

    ftp = ftplib.FTP()
    ftp.connect(dionaea_host, port, timeout=10)
    try:
        ftp.login("anonymous", "test@test.com")
        # PWD should return current directory
        pwd = ftp.pwd()
        assert pwd is not None
    except ftplib.error_perm:
        # Login might fail - that's ok for honeypot
        pass
    finally:
        try:
            ftp.quit()
        except Exception:
            pass


def test_ftp_connection_raw(dionaea_host, dionaea_ports):
    """Test raw TCP connection to FTP port."""
    port = dionaea_ports["ftp"]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((dionaea_host, port))
        # Read banner
        banner = sock.recv(1024)
        assert banner.startswith(b"220"), f"Expected 220 banner, got: {banner}"
    finally:
        sock.close()
