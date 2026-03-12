# ABOUTME: Unit tests for RDP crypto operations.
# ABOUTME: Tests RSA key generation, session key derivation, and RC4 encryption.

# SPDX-FileCopyrightText: 2025 Cowrie <cowrie@cowrie.org>
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial

import struct
import pytest

from dionaea.rdp.include.crypto import (
    generate_rsa_key,
    build_server_security_data,
    decrypt_client_random,
    derive_session_keys,
    rc4_crypt,
    parse_client_info_pdu,
    ClientInfo,
)


class TestRSAKeyGeneration:
    def test_generate_key(self):
        key = generate_rsa_key()
        assert key is not None
        # Should have public numbers
        pub = key.public_key()
        pub_numbers = pub.public_numbers()
        assert pub_numbers.e == 65537

    def test_key_size(self):
        key = generate_rsa_key(key_size=2048)
        assert key.key_size == 2048


class TestServerSecurityData:
    def test_build_security_data(self):
        key = generate_rsa_key()
        data = build_server_security_data(key)
        assert isinstance(data, bytes)
        assert len(data) > 0
        # Should start with encryption method and level
        method, level = struct.unpack_from("<II", data, 0)
        assert method == 0x00000001  # 40-bit
        assert level == 0x00000003   # high

    def test_contains_server_random(self):
        key = generate_rsa_key()
        data = build_server_security_data(key)
        # After method(4) + level(4) + serverRandomLen(4) + serverCertLen(4)
        # comes 32 bytes of server random
        random_len = struct.unpack_from("<I", data, 8)[0]
        assert random_len == 32


class TestClientRandomDecryption:
    def test_round_trip(self):
        key = generate_rsa_key()
        # Simulate what a client would do: encrypt a 32-byte random with server's public key
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        client_random = b"\x42" * 32
        pub = key.public_key()
        encrypted = pub.encrypt(client_random, asym_padding.PKCS1v15())

        # Decrypt should recover the original
        decrypted = decrypt_client_random(key, encrypted)
        assert decrypted == client_random


class TestSessionKeyDerivation:
    def test_derive_keys(self):
        client_random = b"\x11" * 32
        server_random = b"\x22" * 32
        keys = derive_session_keys(client_random, server_random)
        assert "encrypt" in keys
        assert "decrypt" in keys
        assert "mac" in keys
        # Keys should be 16 bytes for 128-bit
        assert len(keys["encrypt"]) > 0
        assert len(keys["decrypt"]) > 0
        assert len(keys["mac"]) > 0

    def test_different_randoms_produce_different_keys(self):
        keys1 = derive_session_keys(b"\x11" * 32, b"\x22" * 32)
        keys2 = derive_session_keys(b"\x33" * 32, b"\x44" * 32)
        assert keys1["encrypt"] != keys2["encrypt"]


class TestRC4:
    def test_round_trip(self):
        key = b"\xAB" * 16
        plaintext = b"Hello, RDP!"
        ciphertext = rc4_crypt(key, plaintext)
        decrypted = rc4_crypt(key, ciphertext)
        assert decrypted == plaintext

    def test_different_keys_produce_different_output(self):
        plaintext = b"test data"
        ct1 = rc4_crypt(b"\x01" * 16, plaintext)
        ct2 = rc4_crypt(b"\x02" * 16, plaintext)
        assert ct1 != ct2


class TestClientInfoPDU:
    def _build_client_info(
        self,
        domain: str = "WORKGROUP",
        username: str = "administrator",
        password: str = "P@ssw0rd",
        alt_shell: str = "",
        working_dir: str = "",
    ) -> bytes:
        """Build a TS_INFO_PACKET payload."""
        # Encode strings as null-terminated UTF-16LE
        domain_bytes = domain.encode("utf-16-le") + b"\x00\x00"
        user_bytes = username.encode("utf-16-le") + b"\x00\x00"
        pass_bytes = password.encode("utf-16-le") + b"\x00\x00"
        shell_bytes = alt_shell.encode("utf-16-le") + b"\x00\x00"
        dir_bytes = working_dir.encode("utf-16-le") + b"\x00\x00"

        # TS_INFO_PACKET fixed header:
        # codePage(4) + flags(4) + cbDomain(2) + cbUserName(2) + cbPassword(2) +
        # cbAlternateShell(2) + cbWorkingDir(2)
        flags = 0x00000033  # INFO_MOUSE | INFO_UNICODE | INFO_LOGONNOTIFY | INFO_MAXIMIZESHELL
        header = struct.pack("<II HHHHH",
            0,       # codePage
            flags,
            len(domain_bytes) - 2,  # cbDomain (excluding null terminator)
            len(user_bytes) - 2,
            len(pass_bytes) - 2,
            len(shell_bytes) - 2,
            len(dir_bytes) - 2,
        )
        return header + domain_bytes + user_bytes + pass_bytes + shell_bytes + dir_bytes

    def test_parse_client_info(self):
        data = self._build_client_info()
        info = parse_client_info_pdu(data)
        assert info is not None
        assert info.domain == "WORKGROUP"
        assert info.username == "administrator"
        assert info.password == "P@ssw0rd"

    def test_parse_different_credentials(self):
        data = self._build_client_info(
            domain="CORP",
            username="admin",
            password="secret123",
        )
        info = parse_client_info_pdu(data)
        assert info is not None
        assert info.domain == "CORP"
        assert info.username == "admin"
        assert info.password == "secret123"

    def test_parse_empty_password(self):
        data = self._build_client_info(password="")
        info = parse_client_info_pdu(data)
        assert info is not None
        assert info.password == ""

    def test_parse_too_short(self):
        assert parse_client_info_pdu(b"\x00" * 10) is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
