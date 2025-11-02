#!/usr/bin/env python3
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2025 Michel
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""Standalone test for MultipartParser that doesn't require dionaea runtime"""

import io
import re
import logging
from email import message_from_binary_file
from email.policy import HTTP

logger = logging.getLogger('http')
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
logger.addHandler(handler)


class MultipartFormField:
    """Represents a single field from multipart/form-data"""
    def __init__(self, name: str, filename: str | None = None, content: bytes = b''):
        self.name = name
        self.filename = filename
        self.content = content
        self.file = io.BytesIO(content)


class MultipartParser:
    """Parser for multipart/form-data using Python's email module"""

    def __init__(self, fp: io.BufferedReader, content_type: str, max_fields: int = 100):
        """
        Parse multipart/form-data from a file-like object

        Args:
            fp: File-like object positioned at start of multipart data
            content_type: The Content-Type header value
            max_fields: Maximum number of fields to parse
        """
        self.fields: dict[str, MultipartFormField] = {}
        self._parse(fp, content_type, max_fields)

    def _parse(self, fp: io.BufferedReader, content_type: str, max_fields: int) -> None:
        """Parse the multipart message"""
        try:
            # Create a synthetic HTTP-like message with headers
            # The email parser needs the Content-Type header to know the boundary
            header_bytes = f"Content-Type: {content_type}\r\n\r\n".encode('utf-8')

            # Combine header and body
            combined = io.BytesIO(header_bytes + fp.read())
            combined.seek(0)

            # Parse using email module
            msg = message_from_binary_file(combined, policy=HTTP)

            field_count = 0
            for part in msg.walk():
                if field_count >= max_fields:
                    logger.warning("Maximum field count reached (%d), stopping parse", max_fields)
                    break

                # Skip the container message itself
                if part.get_content_maintype() == 'multipart':
                    continue

                # Get the Content-Disposition header which contains field name and filename
                content_disp = part.get('Content-Disposition', '')
                if not content_disp:
                    continue

                # Parse Content-Disposition to extract name and filename
                name = self._extract_param(content_disp, 'name')
                if not name:
                    continue

                filename = self._extract_param(content_disp, 'filename')

                # Get the content
                content = part.get_content()
                if isinstance(content, str):
                    # Convert string to bytes if needed
                    content = content.encode('latin-1')

                self.fields[name] = MultipartFormField(name, filename, content)
                field_count += 1

        except Exception as e:
            logger.warning("Failed to parse multipart data: %s", e)
            # For honeypot purposes, we want to be resilient to malformed data

    def _extract_param(self, header_value: str, param_name: str) -> str | None:
        """Extract a parameter from a Content-Disposition header"""
        # Simple regex-based extraction
        # Handles both: name="value" and name=value
        pattern = rf'{param_name}=(?:"([^"]*)"|([^;,\s]*))'
        match = re.search(pattern, header_value, re.IGNORECASE)
        if match:
            return match.group(1) or match.group(2)
        return None

    def keys(self):
        """Return field names"""
        return self.fields.keys()

    def __getitem__(self, key: str) -> MultipartFormField:
        """Access fields like a dictionary"""
        return self.fields[key]


def test_single_file_upload():
    """Test parsing a single file upload"""
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    content_type = f"multipart/form-data; boundary={boundary}"

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

    assert 'file' in parser.keys(), "Field 'file' not found"
    field = parser['file']
    assert field.filename == 'test.txt', f"Expected filename 'test.txt', got '{field.filename}'"
    assert field.content == b'Hello World', f"Content mismatch: {field.content}"
    print("✓ test_single_file_upload passed")


def test_multiple_files():
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

    assert len(list(parser.keys())) == 2, f"Expected 2 fields, got {len(list(parser.keys()))}"
    assert parser['file1'].filename == 'a.txt'
    assert parser['file1'].content == b'Content A'
    assert parser['file2'].filename == 'b.txt'
    assert parser['file2'].content == b'Content B'
    print("✓ test_multiple_files passed")


def test_text_field():
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
    assert field.content == b'testuser'
    print("✓ test_text_field passed")


def test_binary_content():
    """Test parsing binary file content"""
    boundary = "----WebKitFormBoundary"
    content_type = f"multipart/form-data; boundary={boundary}"

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
    print("✓ test_binary_content passed")


def test_max_fields_limit():
    """Test that max_fields limit is respected"""
    boundary = "----WebKitFormBoundary"
    content_type = f"multipart/form-data; boundary={boundary}"

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

    assert len(list(parser.keys())) == 5, f"Expected 5 fields, got {len(list(parser.keys()))}"
    print("✓ test_max_fields_limit passed")


def test_malformed_data_resilience():
    """Test that parser handles malformed data gracefully"""
    content_type = "multipart/form-data; boundary=test"

    data = b"This is not valid multipart data at all!"

    fp = io.BytesIO(data)
    parser = MultipartParser(fp, content_type)

    assert len(list(parser.keys())) == 0
    print("✓ test_malformed_data_resilience passed")


def test_file_attribute_readable():
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
    content = field.file.read(5)
    assert content == b'Hello', f"Expected b'Hello', got {content}"
    content = field.file.read()
    assert content == b' World', f"Expected b' World', got {content}"
    print("✓ test_file_attribute_readable passed")


if __name__ == '__main__':
    print("Running MultipartParser unit tests...\n")
    test_single_file_upload()
    test_multiple_files()
    test_text_field()
    test_binary_content()
    test_max_fields_limit()
    test_malformed_data_resilience()
    test_file_attribute_readable()
    print("\n✅ All tests passed!")
