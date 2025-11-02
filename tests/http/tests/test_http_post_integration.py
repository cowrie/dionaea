# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2025 Michel
#
# SPDX-License-Identifier: GPL-2.0-or-later

import socket
import time


class TestHTTPPostIntegration:
    """Integration tests for HTTP POST with file uploads"""

    def test_single_file_upload_to_server(self):
        """Test uploading a file to the dionaea HTTP server"""
        # Prepare multipart form data
        boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        body = (
            f"------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
            f"Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n"
            f"Content-Type: text/plain\r\n"
            f"\r\n"
            f"This is test content\r\n"
            f"------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n"
        ).encode('utf-8')

        content_length = len(body)

        # Construct HTTP POST request
        request = (
            f"POST /upload HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {content_length}\r\n"
            f"\r\n"
        ).encode('utf-8') + body

        # Connect to dionaea HTTP server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(('127.0.0.1', 8080))
            sock.sendall(request)

            # Read response
            response = b''
            sock.settimeout(2.0)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            # Verify we got a response
            assert b'HTTP/' in response
            # Server should respond with some HTTP status
            assert b'200' in response or b'404' in response or b'405' in response

        finally:
            sock.close()

    def test_multiple_files_upload(self):
        """Test uploading multiple files"""
        boundary = "----WebKitFormBoundary"
        body = (
            f"------WebKitFormBoundary\r\n"
            f"Content-Disposition: form-data; name=\"file1\"; filename=\"a.txt\"\r\n"
            f"\r\n"
            f"File A content\r\n"
            f"------WebKitFormBoundary\r\n"
            f"Content-Disposition: form-data; name=\"file2\"; filename=\"b.txt\"\r\n"
            f"\r\n"
            f"File B content\r\n"
            f"------WebKitFormBoundary--\r\n"
        ).encode('utf-8')

        content_length = len(body)

        request = (
            f"POST /upload HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {content_length}\r\n"
            f"\r\n"
        ).encode('utf-8') + body

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(('127.0.0.1', 8080))
            sock.sendall(request)

            response = b''
            sock.settimeout(2.0)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            assert b'HTTP/' in response

        finally:
            sock.close()

    def test_large_file_upload(self):
        """Test uploading a larger file (10KB)"""
        boundary = "----WebKitFormBoundary"

        # Create 10KB of content
        large_content = b'A' * (10 * 1024)

        header = (
            f"------WebKitFormBoundary\r\n"
            f"Content-Disposition: form-data; name=\"bigfile\"; filename=\"large.bin\"\r\n"
            f"\r\n"
        ).encode('utf-8')

        footer = (
            f"\r\n"
            f"------WebKitFormBoundary--\r\n"
        ).encode('utf-8')

        body = header + large_content + footer
        content_length = len(body)

        request = (
            f"POST /upload HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {content_length}\r\n"
            f"\r\n"
        ).encode('utf-8') + body

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(('127.0.0.1', 8080))
            sock.sendall(request)

            response = b''
            sock.settimeout(2.0)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            assert b'HTTP/' in response

        finally:
            sock.close()

    def test_malformed_multipart_handling(self):
        """Test that server handles malformed multipart data gracefully"""
        # Send malformed multipart data
        body = b"This is not valid multipart data"
        content_length = len(body)

        request = (
            f"POST /upload HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"Content-Type: multipart/form-data; boundary=test\r\n"
            f"Content-Length: {content_length}\r\n"
            f"\r\n"
        ).encode('utf-8') + body

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(('127.0.0.1', 8080))
            sock.sendall(request)

            response = b''
            sock.settimeout(2.0)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            # Server should not crash - should return some response
            assert b'HTTP/' in response

        finally:
            sock.close()
