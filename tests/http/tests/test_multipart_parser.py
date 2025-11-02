# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2025 Michel
#
# SPDX-License-Identifier: GPL-2.0-or-later

import io
import sys
import os

# Add the dionaea modules to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'modules', 'python'))

from dionaea.http import MultipartParser, MultipartFormField


class TestMultipartParser:
    """Unit tests for MultipartParser"""

    def test_single_file_upload(self):
        """Test parsing a single file upload"""
        boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        content_type = f"multipart/form-data; boundary={boundary}"

        # Create multipart data
        data = (
            f"------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
            f"Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n"
            f"Content-Type: text/plain\r\n"
            f"\r\n"
            f"Hello World\r\n"
            f"------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n"
        ).encode('utf-8')

        fp = io.BytesIO(data)
        parser = MultipartParser(fp, content_type)

        assert 'file' in parser.keys()
        field = parser['file']
        assert field.filename == 'test.txt'
        assert field.content == b'Hello World\r\n'

    def test_multiple_files(self):
        """Test parsing multiple file uploads"""
        boundary = "----WebKitFormBoundary"
        content_type = f"multipart/form-data; boundary={boundary}"

        data = (
            f"------WebKitFormBoundary\r\n"
            f"Content-Disposition: form-data; name=\"file1\"; filename=\"a.txt\"\r\n"
            f"\r\n"
            f"Content A\r\n"
            f"------WebKitFormBoundary\r\n"
            f"Content-Disposition: form-data; name=\"file2\"; filename=\"b.txt\"\r\n"
            f"\r\n"
            f"Content B\r\n"
            f"------WebKitFormBoundary--\r\n"
        ).encode('utf-8')

        fp = io.BytesIO(data)
        parser = MultipartParser(fp, content_type)

        assert len(list(parser.keys())) == 2
        assert parser['file1'].filename == 'a.txt'
        assert parser['file1'].content == b'Content A\r\n'
        assert parser['file2'].filename == 'b.txt'
        assert parser['file2'].content == b'Content B\r\n'

    def test_text_field(self):
        """Test parsing a text field (no filename)"""
        boundary = "----WebKitFormBoundary"
        content_type = f"multipart/form-data; boundary={boundary}"

        data = (
            f"------WebKitFormBoundary\r\n"
            f"Content-Disposition: form-data; name=\"username\"\r\n"
            f"\r\n"
            f"testuser\r\n"
            f"------WebKitFormBoundary--\r\n"
        ).encode('utf-8')

        fp = io.BytesIO(data)
        parser = MultipartParser(fp, content_type)

        assert 'username' in parser.keys()
        field = parser['username']
        assert field.filename is None
        assert field.content == b'testuser\r\n'

    def test_mixed_fields_and_files(self):
        """Test parsing a mix of text fields and file uploads"""
        boundary = "----WebKitFormBoundary"
        content_type = f"multipart/form-data; boundary={boundary}"

        data = (
            f"------WebKitFormBoundary\r\n"
            f"Content-Disposition: form-data; name=\"username\"\r\n"
            f"\r\n"
            f"alice\r\n"
            f"------WebKitFormBoundary\r\n"
            f"Content-Disposition: form-data; name=\"upload\"; filename=\"data.bin\"\r\n"
            f"\r\n"
            f"binary data here\r\n"
            f"------WebKitFormBoundary--\r\n"
        ).encode('utf-8')

        fp = io.BytesIO(data)
        parser = MultipartParser(fp, content_type)

        assert len(list(parser.keys())) == 2
        assert parser['username'].filename is None
        assert parser['upload'].filename == 'data.bin'

    def test_binary_content(self):
        """Test parsing binary file content"""
        boundary = "----WebKitFormBoundary"
        content_type = f"multipart/form-data; boundary={boundary}"

        # Create multipart data with actual binary content
        header = (
            f"------WebKitFormBoundary\r\n"
            f"Content-Disposition: form-data; name=\"binary\"; filename=\"data.bin\"\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"\r\n"
        ).encode('utf-8')

        binary_content = bytes([0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD])

        footer = (
            f"\r\n"
            f"------WebKitFormBoundary--\r\n"
        ).encode('utf-8')

        data = header + binary_content + footer

        fp = io.BytesIO(data)
        parser = MultipartParser(fp, content_type)

        assert 'binary' in parser.keys()
        field = parser['binary']
        assert field.filename == 'data.bin'
        assert binary_content in field.content

    def test_max_fields_limit(self):
        """Test that max_fields limit is respected"""
        boundary = "----WebKitFormBoundary"
        content_type = f"multipart/form-data; boundary={boundary}"

        # Create 10 fields but set max to 5
        parts = []
        for i in range(10):
            parts.append(
                f"------WebKitFormBoundary\r\n"
                f"Content-Disposition: form-data; name=\"field{i}\"\r\n"
                f"\r\n"
                f"value{i}\r\n"
            )
        parts.append(f"------WebKitFormBoundary--\r\n")

        data = "".join(parts).encode('utf-8')

        fp = io.BytesIO(data)
        parser = MultipartParser(fp, content_type, max_fields=5)

        # Should only parse first 5 fields
        assert len(list(parser.keys())) == 5

    def test_malformed_data_resilience(self):
        """Test that parser handles malformed data gracefully"""
        content_type = "multipart/form-data; boundary=test"

        # Completely invalid multipart data
        data = b"This is not valid multipart data at all!"

        fp = io.BytesIO(data)
        parser = MultipartParser(fp, content_type)

        # Should not crash, just return empty
        assert len(list(parser.keys())) == 0

    def test_missing_boundary(self):
        """Test handling of Content-Type without boundary"""
        content_type = "multipart/form-data"
        data = b"some data"

        fp = io.BytesIO(data)
        parser = MultipartParser(fp, content_type)

        # Should handle gracefully
        assert len(list(parser.keys())) == 0

    def test_filename_with_quotes(self):
        """Test parsing filename with quotes in Content-Disposition"""
        boundary = "----WebKitFormBoundary"
        content_type = f"multipart/form-data; boundary={boundary}"

        data = (
            f"------WebKitFormBoundary\r\n"
            f'Content-Disposition: form-data; name="file"; filename="test file.txt"\r\n'
            f"\r\n"
            f"content\r\n"
            f"------WebKitFormBoundary--\r\n"
        ).encode('utf-8')

        fp = io.BytesIO(data)
        parser = MultipartParser(fp, content_type)

        assert parser['file'].filename == 'test file.txt'

    def test_file_attribute_readable(self):
        """Test that the .file attribute can be read like a file"""
        boundary = "----WebKitFormBoundary"
        content_type = f"multipart/form-data; boundary={boundary}"

        data = (
            f"------WebKitFormBoundary\r\n"
            f"Content-Disposition: form-data; name=\"upload\"; filename=\"test.txt\"\r\n"
            f"\r\n"
            f"Hello World\r\n"
            f"------WebKitFormBoundary--\r\n"
        ).encode('utf-8')

        fp = io.BytesIO(data)
        parser = MultipartParser(fp, content_type)

        field = parser['upload']
        # Test reading from the file attribute
        content = field.file.read(5)
        assert content == b'Hello'
        content = field.file.read()
        assert content == b' World\r\n'
