# ABOUTME: RDP standard security crypto operations.
# ABOUTME: RSA key gen, session key derivation, RC4 encryption, and Client Info PDU parsing.

import hashlib
import os
import struct
from typing import NamedTuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import ARC4  # type: ignore[attr-defined]


def generate_rsa_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Generate an RSA private key for the RDP security exchange."""
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def _rsa_public_key_blob(key: rsa.RSAPrivateKey) -> bytes:
    """Build the proprietary server certificate RSA public key blob.

    Format: magic(4) + keylen(4) + bitlen(4) + datalen(4) + pubExp(4) + modulus(keylen)
    """
    pub = key.public_key().public_numbers()
    key_bytes = key.key_size // 8
    modulus = pub.n.to_bytes(key_bytes, "little")

    return struct.pack("<IIIII",
        0x31415352,   # RSA1 magic
        key_bytes + 8,  # keylen (modulus + padding)
        key.key_size,   # bitlen
        key_bytes - 1,  # datalen (max bytes that can be encrypted)
        pub.e,          # public exponent
    ) + modulus + b"\x00" * 8  # padding


def build_server_security_data(key: rsa.RSAPrivateKey) -> bytes:
    """Build the SC_SECURITY server data block payload for MCS Connect-Response.

    Contains encryption method/level, server random, and proprietary certificate.
    Returns raw payload (caller wraps in SC_SECURITY block header).
    """
    server_random = os.urandom(32)

    # Proprietary certificate: version(4) + signatureType(4) +
    # keyBlob { wBlobType(2) + wBlobLen(2) + data } + sigBlob { ... }
    pub_blob = _rsa_public_key_blob(key)
    key_blob = struct.pack("<HH", 0x0006, len(pub_blob)) + pub_blob  # BB_RSA_KEY_BLOB

    # Signature: we use a zero signature since clients with standard security
    # don't typically verify the proprietary cert signature
    sig_data = b"\x00" * 72
    sig_blob = struct.pack("<HH", 0x0008, len(sig_data)) + sig_data  # BB_RSA_SIGNATURE_BLOB

    cert = struct.pack("<II",
        0x00000001,  # dwVersion = CERT_CHAIN_VERSION_1 (proprietary)
        0x00000001,  # dwSigAlgId = SIGNATURE_ALG_RSA
    ) + key_blob + sig_blob

    return struct.pack("<IIII",
        0x00000001,  # encryptionMethod = ENCRYPTION_METHOD_40BIT
        0x00000003,  # encryptionLevel = ENCRYPTION_LEVEL_HIGH
        32,          # serverRandomLen
        len(cert),   # serverCertLen
    ) + server_random + cert


def decrypt_client_random(key: rsa.RSAPrivateKey, encrypted: bytes) -> bytes:
    """Decrypt the client random from the Security Exchange PDU."""
    return key.decrypt(encrypted, asym_padding.PKCS1v15())


def _salted_hash(secret: bytes, client_random: bytes, server_random: bytes, salt: bytes) -> bytes:
    """Compute SaltedHash(secret, salt) = MD5(secret + SHA1(salt + secret + clientRandom + serverRandom))."""
    sha1 = hashlib.sha1(salt + secret + client_random + server_random).digest()
    return hashlib.md5(secret + sha1).digest()


def derive_session_keys(
    client_random: bytes,
    server_random: bytes,
) -> dict[str, bytes]:
    """Derive RDP session keys from client and server randoms.

    Returns dict with 'encrypt', 'decrypt', and 'mac' keys.
    Uses the "non-FIPS" key derivation from MS-RDPBCGR 5.3.5.
    """
    pre_master_secret = client_random[:24] + server_random[:24]

    # MasterSecret = SaltedHash("A") + SaltedHash("BB") + SaltedHash("CCC")
    master_secret = b""
    for i, salt in enumerate([b"A", b"BB", b"CCC"]):
        master_secret += _salted_hash(pre_master_secret, client_random, server_random, salt)

    # SessionKeyBlob = SaltedHash("X") + SaltedHash("YY") + SaltedHash("ZZZ")
    session_key_blob = b""
    for salt in [b"X", b"YY", b"ZZZ"]:
        session_key_blob += _salted_hash(master_secret, client_random, server_random, salt)

    # Initial encryption key = First 16 bytes
    # MAC key = last 16 bytes of first 32
    mac_key = session_key_blob[:16]
    encrypt_key = _final_hash(session_key_blob[16:32], client_random, server_random)
    decrypt_key = _final_hash(session_key_blob[32:48], client_random, server_random)

    return {
        "encrypt": encrypt_key,
        "decrypt": decrypt_key,
        "mac": mac_key,
    }


def _final_hash(key: bytes, client_random: bytes, server_random: bytes) -> bytes:
    """FinalHash(key) = MD5(key + clientRandom + serverRandom)."""
    return hashlib.md5(key + client_random + server_random).digest()


def rc4_crypt(key: bytes, data: bytes) -> bytes:
    """Encrypt or decrypt data using RC4 (ARC4)."""
    cipher = Cipher(ARC4(key), mode=None)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


class ClientInfo(NamedTuple):
    """Parsed credentials from TS_INFO_PACKET."""
    domain: str
    username: str
    password: str
    alt_shell: str
    working_dir: str


def parse_client_info_pdu(data: bytes) -> ClientInfo | None:
    """Parse TS_INFO_PACKET to extract credentials.

    Input: raw info packet data (after security header).
    """
    # Fixed header: codePage(4) + flags(4) + cbDomain(2) + cbUserName(2) +
    # cbPassword(2) + cbAlternateShell(2) + cbWorkingDir(2) = 18 bytes
    if len(data) < 18:
        return None

    (code_page, flags,
     cb_domain, cb_user, cb_password,
     cb_shell, cb_dir) = struct.unpack_from("<II HHHHH", data, 0)

    is_unicode = bool(flags & 0x00000010)  # INFO_UNICODE
    encoding = "utf-16-le" if is_unicode else "ascii"
    null_term_len = 2 if is_unicode else 1

    offset = 18

    def read_field(length: int) -> str:
        nonlocal offset
        # length is cbField (excludes null terminator), read length + null_term_len
        field_data = data[offset:offset + length]
        offset += length + null_term_len
        return field_data.decode(encoding, errors="replace")

    try:
        domain = read_field(cb_domain)
        username = read_field(cb_user)
        password = read_field(cb_password)
        alt_shell = read_field(cb_shell)
        working_dir = read_field(cb_dir)
    except Exception:
        return None

    return ClientInfo(
        domain=domain,
        username=username,
        password=password,
        alt_shell=alt_shell,
        working_dir=working_dir,
    )
