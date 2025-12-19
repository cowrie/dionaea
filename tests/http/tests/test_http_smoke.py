# ABOUTME: HTTP protocol smoke tests for dionaea honeypot
# ABOUTME: Tests basic GET and POST requests using requests library

# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

import socket

import requests


def test_http_get_root(dionaea_host, dionaea_ports):
    """Test HTTP GET / returns a response."""
    port = dionaea_ports["http"]
    url = f"http://{dionaea_host}:{port}/"

    response = requests.get(url, timeout=10)
    # Any response is acceptable for a honeypot
    assert response.status_code in range(100, 600)


def test_http_get_nonexistent(dionaea_host, dionaea_ports):
    """Test HTTP GET for non-existent path."""
    port = dionaea_ports["http"]
    url = f"http://{dionaea_host}:{port}/nonexistent/path/file.txt"

    response = requests.get(url, timeout=10)
    # 404 or any other response is fine
    assert response.status_code in range(100, 600)


def test_http_post_form(dionaea_host, dionaea_ports):
    """Test HTTP POST with form data."""
    port = dionaea_ports["http"]
    url = f"http://{dionaea_host}:{port}/"

    data = {"field1": "value1", "field2": "value2"}
    response = requests.post(url, data=data, timeout=10)
    assert response.status_code in range(100, 600)


def test_http_post_json(dionaea_host, dionaea_ports):
    """Test HTTP POST with JSON data."""
    port = dionaea_ports["http"]
    url = f"http://{dionaea_host}:{port}/"

    data = {"key": "value", "number": 42}
    response = requests.post(url, json=data, timeout=10)
    assert response.status_code in range(100, 600)


def test_http_head_request(dionaea_host, dionaea_ports):
    """Test HTTP HEAD request."""
    port = dionaea_ports["http"]
    url = f"http://{dionaea_host}:{port}/"

    response = requests.head(url, timeout=10)
    assert response.status_code in range(100, 600)


def test_http_options_request(dionaea_host, dionaea_ports):
    """Test HTTP OPTIONS request."""
    port = dionaea_ports["http"]
    url = f"http://{dionaea_host}:{port}/"

    response = requests.options(url, timeout=10)
    assert response.status_code in range(100, 600)


def test_http_connection_raw(dionaea_host, dionaea_ports):
    """Test raw TCP connection and HTTP/1.1 request."""
    port = dionaea_ports["http"]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((dionaea_host, port))
        request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        sock.sendall(request)
        response = sock.recv(4096)
        # Should start with HTTP version
        assert response.startswith(b"HTTP/")
    finally:
        sock.close()
